from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

import os
import sqlite3
import smtplib
import secrets
import hashlib
import traceback
from email.message import EmailMessage
from datetime import datetime, timedelta

from dotenv import load_dotenv
load_dotenv()  # reads variables from a .env file in the project root, if present

import psycopg

from psycopg.rows import dict_row

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "labelpro_ai_secret_key_2026"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)



# =========================================================
# EMAIL / OTP CONFIGURATION
# =========================================================

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME)

OTP_EXPIRY_MINUTES = 10
OTP_RESEND_SECONDS = 60

if not SMTP_USERNAME or not SMTP_PASSWORD:
    print(
        "WARNING: SMTP_USERNAME / SMTP_PASSWORD are not set. "
        "OTP emails will fail until these are configured in your .env file. "
        "See .env.example for the required variables."
    )


def hash_otp(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def generate_otp():
    return f"{secrets.randbelow(1000000):06d}"


def send_otp_email(to_email, otp, purpose="verification"):
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        raise RuntimeError("SMTP credentials are not configured on the server.")

    if purpose == "verification":
        subject = "Verify your LabelPro AI Academy account"
        title = "Verify your email"
        message = "Use this OTP to verify your LabelPro AI Academy account."
    else:
        subject = "Reset your LabelPro AI Academy password"
        title = "Password reset code"
        message = "Use this OTP to reset your LabelPro AI Academy password."

    email = EmailMessage()
    email["Subject"] = subject
    email["From"] = SMTP_FROM or SMTP_USERNAME
    email["To"] = to_email
    email.set_content(
        f"{title}\n\n{message}\n\n"
        f"Your OTP is: {otp}\n\n"
        f"This code expires in {OTP_EXPIRY_MINUTES} minutes.\n"
        "If you did not request this, you can ignore this email."
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(email)
    except Exception:
        # Print the full traceback so the real cause (bad host/port,
        # wrong credentials, blocked login, etc.) shows up in the
        # server console instead of a vague error.
        print("SMTP SEND FAILED:")
        traceback.print_exc()
        raise

    print(f"OTP email sent successfully to {to_email} ({purpose})")


def send_new_otp(email, purpose):
    otp = generate_otp()
    session[f"{purpose}_otp_hash"] = hash_otp(otp)
    session[f"{purpose}_otp_expires"] = (
        datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    ).isoformat()
    session[f"{purpose}_last_sent"] = datetime.utcnow().isoformat()
    session[f"{purpose}_email"] = email
    send_otp_email(email, otp, purpose)


def otp_is_valid(code, purpose):
    stored_hash = session.get(f"{purpose}_otp_hash")
    expires = session.get(f"{purpose}_otp_expires")

    if not stored_hash or not expires:
        return False

    try:
        expiry_time = datetime.fromisoformat(expires)
    except ValueError:
        return False

    if datetime.utcnow() > expiry_time:
        return False

    return secrets.compare_digest(hash_otp(code), stored_hash)


def can_resend_otp(purpose):
    last_sent = session.get(f"{purpose}_last_sent")
    if not last_sent:
        return True
    try:
        last = datetime.fromisoformat(last_sent)
    except ValueError:
        return True
    return (datetime.utcnow() - last).total_seconds() >= OTP_RESEND_SECONDS


def clear_otp_session(purpose):
    for key in (
        f"{purpose}_otp_hash",
        f"{purpose}_otp_expires",
        f"{purpose}_last_sent",
        f"{purpose}_email",
    ):
        session.pop(key, None)


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

DATABASE_URL = os.getenv("DATABASE_URL")

SQLITE_DATABASE = "database.db"


def using_postgresql():

    return bool(DATABASE_URL)


def get_db():

    # -------------------------
    # POSTGRESQL - RENDER
    # -------------------------

    if using_postgresql():

        conn = psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row
        )

        return conn

    # -------------------------
    # SQLITE - LOCAL
    # -------------------------

    conn = sqlite3.connect(
        SQLITE_DATABASE
    )

    conn.row_factory = sqlite3.Row

    return conn


# =========================================================
# CREATE DATABASE TABLES
# =========================================================

def create_tables():

    conn = get_db()

    try:

        # =================================================
        # POSTGRESQL
        # =================================================

        if using_postgresql():

            # -------------------------
            # USERS TABLE
            # -------------------------

            conn.execute("""
                CREATE TABLE IF NOT EXISTS users(

                    id SERIAL PRIMARY KEY,

                    name TEXT NOT NULL,

                    email TEXT UNIQUE NOT NULL,

                    phone TEXT NOT NULL,

                    password TEXT NOT NULL,

                    is_verified BOOLEAN NOT NULL DEFAULT FALSE,

                    created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # -------------------------
            # COURSES TABLE
            # -------------------------

            conn.execute("""
                CREATE TABLE IF NOT EXISTS courses(

                    id SERIAL PRIMARY KEY,

                    title TEXT NOT NULL,

                    description TEXT NOT NULL,

                    duration TEXT NOT NULL,

                    level TEXT NOT NULL,

                    thumbnail TEXT,

                    created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # -------------------------
            # LESSONS TABLE
            # -------------------------

            conn.execute("""
                CREATE TABLE IF NOT EXISTS lessons(

                    id SERIAL PRIMARY KEY,

                    course_id INTEGER NOT NULL,

                    title TEXT NOT NULL,

                    content TEXT NOT NULL,

                    lesson_order INTEGER
                    DEFAULT 1,

                    created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
                )
            """)

        # =================================================
        # SQLITE
        # =================================================

        else:

            # -------------------------
            # USERS TABLE
            # -------------------------

            conn.execute("""
                CREATE TABLE IF NOT EXISTS users(

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    name TEXT NOT NULL,

                    email TEXT UNIQUE NOT NULL,

                    phone TEXT NOT NULL,

                    password TEXT NOT NULL,

                    is_verified BOOLEAN NOT NULL DEFAULT FALSE,

                    created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # -------------------------
            # COURSES TABLE
            # -------------------------

            conn.execute("""
                CREATE TABLE IF NOT EXISTS courses(

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    title TEXT NOT NULL,

                    description TEXT NOT NULL,

                    duration TEXT NOT NULL,

                    level TEXT NOT NULL,

                    thumbnail TEXT,

                    created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # -------------------------
            # LESSONS TABLE
            # -------------------------

            conn.execute("""
                CREATE TABLE IF NOT EXISTS lessons(

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    course_id INTEGER NOT NULL,

                    title TEXT NOT NULL,

                    content TEXT NOT NULL,

                    lesson_order INTEGER
                    DEFAULT 1,

                    created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
                )
            """)

        # -------------------------------------------------
        # Migrate existing deployments
        # -------------------------------------------------
        # Older databases do not have is_verified. Existing
        # accounts are marked verified so login keeps working.
        try:
            if using_postgresql():
                conn.execute(
                    "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                    "is_verified BOOLEAN NOT NULL DEFAULT TRUE"
                )
            else:
                columns = conn.execute("PRAGMA table_info(users)").fetchall()
                column_names = [row[1] for row in columns]
                if "is_verified" not in column_names:
                    conn.execute(
                        "ALTER TABLE users ADD COLUMN "
                        "is_verified INTEGER NOT NULL DEFAULT 1"
                    )
        except Exception as migration_error:
            print("USER TABLE MIGRATION WARNING:", migration_error)

        conn.commit()

        print(
            "DATABASE TABLES CREATED SUCCESSFULLY"
        )

    except Exception as e:

        conn.rollback()

        print(
            "DATABASE TABLE ERROR:",
            e
        )

    finally:

        conn.close()


# Create tables when application starts

create_tables()


# =========================================================
# GET ALL COURSES
# =========================================================

def get_all_courses():

    conn = get_db()

    try:

        print(
            "DATABASE:",
            "POSTGRESQL"
            if using_postgresql()
            else "SQLITE"
        )

        courses = conn.execute("""
            SELECT *
            FROM courses
            ORDER BY id DESC
        """).fetchall()

        print(
            "COURSES FOUND:",
            len(courses)
        )

        return courses

    except Exception as e:

        print(
            "GET COURSES ERROR:",
            e
        )

        return []

    finally:

        conn.close()


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    # Public landing page should be shown at the root URL.
    # Login is available separately at /login.
    return render_template("index.html")


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not name or not email or not phone or not password:
            flash("Please fill all fields.", "danger")
            return redirect(url_for("register"))

        if "@" not in email or "." not in email.split("@")[-1]:
            flash("Please enter a valid email address.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        conn = get_db()

        try:
            if using_postgresql():
                existing = conn.execute(
                    "SELECT * FROM users WHERE email = %s",
                    (email,)
                ).fetchone()
            else:
                existing = conn.execute(
                    "SELECT * FROM users WHERE email = ?",
                    (email,)
                ).fetchone()

            if existing:
                # If an old/unverified account exists, allow the user
                # to request verification again instead of creating a duplicate.
                try:
                    verified = bool(existing["is_verified"])
                except Exception:
                    verified = True

                if not verified:
                    session.clear()
                    session["pending_email"] = email
                    try:
                        send_new_otp(email, "verification")
                        flash("A new verification OTP has been sent to your email.", "success")
                        return redirect(url_for("verify_email"))
                    except Exception as email_error:
                        print("VERIFICATION EMAIL ERROR:", email_error)
                        flash("Could not send the OTP. Please check the server email settings.", "danger")
                        return redirect(url_for("register"))

                flash("Email already registered.", "warning")
                return redirect(url_for("register"))

            hashed_password = generate_password_hash(password)

            if using_postgresql():
                conn.execute(
                    """
                    INSERT INTO users
                    (name, email, phone, password, is_verified)
                    VALUES (%s, %s, %s, %s, FALSE)
                    """,
                    (name, email, phone, hashed_password)
                )
            else:
                conn.execute(
                    """
                    INSERT INTO users
                    (name, email, phone, password, is_verified)
                    VALUES (?, ?, ?, ?, 0)
                    """,
                    (name, email, phone, hashed_password)
                )

            conn.commit()

            session.clear()
            session["pending_email"] = email

            try:
                send_new_otp(email, "verification")
            except Exception as email_error:
                print("VERIFICATION EMAIL ERROR:", email_error)
                # Keep the account so it can be verified by resend later.
                flash(
                    "Account created, but the verification email could not be sent. "
                    "Please check SMTP settings and use resend verification.",
                    "danger"
                )
                return redirect(url_for("verify_email"))

            flash("Registration successful! Check your email for the OTP.", "success")
            return redirect(url_for("verify_email"))

        except Exception as e:
            conn.rollback()
            print("REGISTRATION ERROR:", e)
            flash("Registration failed. Please try again.", "danger")
            return redirect(url_for("register"))
        finally:
            conn.close()

    return render_template("register.html")


# =========================================================
# EMAIL VERIFICATION
# =========================================================

@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():

    email = session.get("pending_email") or session.get("verification_email")

    if not email:
        flash("Please register first.", "warning")
        return redirect(url_for("register"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()

        if not otp_is_valid(code, "verification"):
            flash("Invalid or expired OTP.", "danger")
            return redirect(url_for("verify_email"))

        conn = get_db()
        try:
            if using_postgresql():
                conn.execute(
                    "UPDATE users SET is_verified = TRUE WHERE email = %s",
                    (email,)
                )
            else:
                conn.execute(
                    "UPDATE users SET is_verified = 1 WHERE email = ?",
                    (email,)
                )
            conn.commit()
        except Exception as e:
            conn.rollback()
            print("EMAIL VERIFICATION ERROR:", e)
            flash("Verification failed. Please try again.", "danger")
            return redirect(url_for("verify_email"))
        finally:
            conn.close()

        clear_otp_session("verification")
        session.pop("pending_email", None)
        session.pop("verification_email", None)

        flash("Email verified successfully. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("verify_otp.html", email=email, purpose="verification")


@app.route("/resend-verification", methods=["POST"])
def resend_verification():

    email = session.get("pending_email") or session.get("verification_email")

    if not email:
        flash("Verification session expired. Please register again.", "warning")
        return redirect(url_for("register"))

    if not can_resend_otp("verification"):
        flash("Please wait 60 seconds before requesting another OTP.", "warning")
        return redirect(url_for("verify_email"))

    try:
        send_new_otp(email, "verification")
        flash("A new verification OTP has been sent.", "success")
    except Exception as e:
        print("RESEND VERIFICATION ERROR:", e)
        flash("Could not send OTP. Please try again later.", "danger")

    return redirect(url_for("verify_email"))


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()

        try:
            if using_postgresql():
                user = conn.execute(
                    "SELECT * FROM users WHERE email = %s",
                    (email,)
                ).fetchone()
            else:
                user = conn.execute(
                    "SELECT * FROM users WHERE email = ?",
                    (email,)
                ).fetchone()
        except Exception as e:
            print("LOGIN ERROR:", e)
            user = None
        finally:
            conn.close()

        if user and check_password_hash(user["password"], password):

            try:
                verified = bool(user["is_verified"])
            except Exception:
                verified = True

            if not verified:
                session.clear()
                session["pending_email"] = email
                if can_resend_otp("verification"):
                    try:
                        send_new_otp(email, "verification")
                        flash("Please verify your email. A new OTP has been sent.", "warning")
                    except Exception as e:
                        print("LOGIN VERIFICATION EMAIL ERROR:", e)
                        flash("Please verify your email using the OTP already sent.", "warning")
                else:
                    flash("Please verify your email using the OTP already sent.", "warning")
                return redirect(url_for("verify_email"))

            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]

            flash("Login Successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid Email or Password", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


# =========================================================
# FORGOT PASSWORD
# =========================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        # Do not reveal whether an account exists.
        conn = get_db()
        user = None
        try:
            if using_postgresql():
                user = conn.execute(
                    "SELECT * FROM users WHERE email = %s",
                    (email,)
                ).fetchone()
            else:
                user = conn.execute(
                    "SELECT * FROM users WHERE email = ?",
                    (email,)
                ).fetchone()
        except Exception as e:
            print("FORGOT PASSWORD LOOKUP ERROR:", e)
        finally:
            conn.close()

        if user:
            if not can_resend_otp("reset"):
                flash("Please wait 60 seconds before requesting another reset code.", "warning")
                return redirect(url_for("forgot_password"))

            try:
                session.clear()
                session["reset_email"] = email
                send_new_otp(email, "reset")
            except Exception as e:
                print("RESET EMAIL ERROR:", e)
                flash("We could not send the reset code right now. Please try again later.", "danger")
                return redirect(url_for("forgot_password"))

        flash("If an account with that email exists, a password reset OTP has been sent.", "success")
        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")


# =========================================================
# RESET PASSWORD
# =========================================================

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    email = session.get("reset_email")

    if not email:
        flash("Please request a password reset first.", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        otp = request.form.get("otp", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not otp_is_valid(otp, "reset"):
            flash("Invalid or expired reset OTP.", "danger")
            return redirect(url_for("reset_password"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("reset_password"))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("reset_password"))

        conn = get_db()

        try:
            hashed_password = generate_password_hash(password)

            if using_postgresql():
                conn.execute(
                    "UPDATE users SET password = %s, is_verified = TRUE WHERE email = %s",
                    (hashed_password, email)
                )
            else:
                conn.execute(
                    "UPDATE users SET password = ?, is_verified = 1 WHERE email = ?",
                    (hashed_password, email)
                )

            conn.commit()

            clear_otp_session("reset")
            session.pop("reset_email", None)

            flash("Password reset successfully. Please log in.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            conn.rollback()
            print("PASSWORD RESET ERROR:", e)
            flash("Could not reset password. Please try again.", "danger")
            return redirect(url_for("reset_password"))
        finally:
            conn.close()

    return render_template("reset_password.html", email=email)


@app.route("/resend-reset-code", methods=["POST"])
def resend_reset_code():

    email = session.get("reset_email")

    if not email:
        flash("Please request a password reset first.", "warning")
        return redirect(url_for("forgot_password"))

    if not can_resend_otp("reset"):
        flash("Please wait 60 seconds before requesting another OTP.", "warning")
        return redirect(url_for("reset_password"))

    try:
        send_new_otp(email, "reset")
        flash("A new reset OTP has been sent.", "success")
    except Exception as e:
        print("RESEND RESET OTP ERROR:", e)
        flash("Could not send the reset OTP. Please try again later.", "danger")

    return redirect(url_for("reset_password"))


# =========================================================
# USER DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    courses = get_all_courses()

    return render_template(
        "dashboard.html",
        username=session["user_name"],
        courses=courses
    )


# =========================================================
# ADMIN CONFIGURATION
# =========================================================

ADMIN_EMAIL = os.getenv(
    "ADMIN_EMAIL",
    "admin@labelpro.ai"
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD",
    ""
)


# =========================================================
# ADMIN LOGIN
# =========================================================

@app.route(
    "/admin",
    methods=["GET", "POST"]
)
def admin():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if (
            ADMIN_PASSWORD
            and
            email == ADMIN_EMAIL.lower()
            and
            secrets.compare_digest(password, ADMIN_PASSWORD)
        ):

            session.clear()
            session.permanent = True
            session["admin"] = True

            return redirect(
                url_for("admin_dashboard")
            )

        flash(
            "Invalid Admin Email or Password",
            "danger"
        )

    return render_template(
        "admin_login.html"
    )


# =========================================================
# ADMIN LOGOUT
# =========================================================

@app.route("/admin/logout")
def admin_logout():

    session.clear()

    flash("Admin logged out successfully.", "success")

    return redirect(url_for("admin"))


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route(
    "/admin/dashboard",
    methods=["GET", "POST"]
)
def admin_dashboard():

    # -------------------------
    # ADMIN LOGIN CHECK
    # -------------------------

    if not session.get("admin"):

        return redirect(
            url_for("admin")
        )

    conn = get_db()

    try:

        # =================================================
        # ADD NEW COURSE
        # =================================================

        if request.method == "POST":

            title = request.form.get(
                "title",
                ""
            ).strip()

            description = request.form.get(
                "description",
                ""
            ).strip()

            duration = request.form.get(
                "duration",
                ""
            ).strip()

            level = request.form.get(
                "level",
                ""
            ).strip()

            # -------------------------
            # VALIDATION
            # -------------------------

            if not title:

                flash(
                    "Course title is required.",
                    "error"
                )

                return redirect(
                    url_for("admin_dashboard")
                )

            # -------------------------
            # INSERT COURSE
            # -------------------------

            if using_postgresql():

                conn.execute(
                    """
                    INSERT INTO courses
                    (
                        title,
                        description,
                        duration,
                        level
                    )
                    VALUES
                    (%s, %s, %s, %s)
                    """,
                    (
                        title,
                        description,
                        duration,
                        level
                    )
                )

            else:

                conn.execute(
                    """
                    INSERT INTO courses
                    (
                        title,
                        description,
                        duration,
                        level
                    )
                    VALUES
                    (?, ?, ?, ?)
                    """,
                    (
                        title,
                        description,
                        duration,
                        level
                    )
                )

            conn.commit()

            flash(
                "Course added successfully.",
                "success"
            )

            return redirect(
                url_for("admin_dashboard")
            )

        # =================================================
        # GET ALL COURSES
        # =================================================

        courses = conn.execute(
            """
            SELECT *
            FROM courses
            ORDER BY id DESC
            """
        ).fetchall()

        # =================================================
        # GET REGISTERED STUDENTS
        # =================================================
        # Never send the password hash to the admin template.
        # The admin panel only needs basic account information.
        students = conn.execute(
            """
            SELECT id, name, email, phone, is_verified, created_at
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()

        # =================================================
        # GET LESSON COUNT
        # =================================================

        course_data = []

        for course in courses:

            if using_postgresql():

                lesson_count = conn.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM lessons
                    WHERE course_id = %s
                    """,
                    (course["id"],)
                ).fetchone()

            else:

                lesson_count = conn.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM lessons
                    WHERE course_id = ?
                    """,
                    (course["id"],)
                ).fetchone()

            course_data.append({

                "course": course,

                "lesson_count":
                    lesson_count["total"]

            })

        # =================================================
        # RENDER ADMIN DASHBOARD
        # =================================================

        return render_template(
            "admin_dashboard.html",
            courses=course_data,
            students=students
        )

    except Exception as e:

        print(
            "ADMIN DASHBOARD ERROR:",
            e
        )

        flash(
            "Something went wrong.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    finally:

        conn.close()


# =========================================================
# ADMIN ADD LESSON
# =========================================================

@app.route(
    "/admin/course/<int:course_id>/add-lesson",
    methods=["GET", "POST"]
)
def admin_add_lesson(course_id):

    # -------------------------
    # ADMIN LOGIN CHECK
    # -------------------------

    if not session.get("admin"):

        return redirect(
            url_for("admin")
        )

    conn = get_db()

    try:

        # =================================================
        # GET COURSE
        # =================================================

        if using_postgresql():

            course = conn.execute(
                """
                SELECT *
                FROM courses
                WHERE id = %s
                """,
                (course_id,)
            ).fetchone()

        else:

            course = conn.execute(
                """
                SELECT *
                FROM courses
                WHERE id = ?
                """,
                (course_id,)
            ).fetchone()

        # =================================================
        # COURSE NOT FOUND
        # =================================================

        if not course:

            flash(
                "Course not found.",
                "error"
            )

            return redirect(
                url_for("admin_dashboard")
            )

        # =================================================
        # ADD LESSON
        # =================================================

        if request.method == "POST":

            title = request.form.get(
                "title",
                ""
            ).strip()

            content = request.form.get(
                "content",
                ""
            ).strip()

            lesson_order = request.form.get(
                "lesson_order",
                "1"
            ).strip()

            # -------------------------
            # VALIDATION
            # -------------------------

            if not title:

                flash(
                    "Lesson title is required.",
                    "error"
                )

                return render_template(
                    "admin_add_lesson.html",
                    course=course
                )

            if not content:

                flash(
                    "Lesson content is required.",
                    "error"
                )

                return render_template(
                    "admin_add_lesson.html",
                    course=course
                )

            # -------------------------
            # LESSON ORDER
            # -------------------------

            try:

                lesson_order = int(
                    lesson_order
                )

            except ValueError:

                lesson_order = 1

            # =================================================
            # INSERT LESSON
            # =================================================

            if using_postgresql():

                conn.execute(
                    """
                    INSERT INTO lessons
                    (
                        course_id,
                        title,
                        content,
                        lesson_order
                    )
                    VALUES
                    (%s, %s, %s, %s)
                    """,
                    (
                        course_id,
                        title,
                        content,
                        lesson_order
                    )
                )

            else:

                conn.execute(
                    """
                    INSERT INTO lessons
                    (
                        course_id,
                        title,
                        content,
                        lesson_order
                    )
                    VALUES
                    (?, ?, ?, ?)
                    """,
                    (
                        course_id,
                        title,
                        content,
                        lesson_order
                    )
                )

            conn.commit()

            flash(
                "Lesson added successfully.",
                "success"
            )

            return redirect(
                url_for("admin_dashboard")
            )

        # =================================================
        # SHOW ADD LESSON PAGE
        # =================================================

        return render_template(
            "admin_add_lesson.html",
            course=course
        )

    except Exception as e:

        print(
            "ADD LESSON ERROR:",
            e
        )

        flash(
            "Something went wrong while adding lesson.",
            "error"
        )

        return redirect(
            url_for("admin_dashboard")
        )

    finally:

        conn.close()


# =========================================================
# COURSE LIST
# =========================================================

@app.route("/course")
def course():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    courses = get_all_courses()

    return render_template(
        "course.html",
        username=session["user_name"],
        courses=courses
    )


# =========================================================
# COURSE DETAIL
# =========================================================

@app.route(
    "/course/<int:course_id>"
)
def course_detail(course_id):

    # -------------------------
    # USER LOGIN CHECK
    # -------------------------

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    conn = get_db()

    try:

        # -------------------------
        # GET COURSE
        # -------------------------

        if using_postgresql():

            course = conn.execute(
                """
                SELECT *
                FROM courses
                WHERE id = %s
                """,
                (course_id,)
            ).fetchone()

        else:

            course = conn.execute(
                """
                SELECT *
                FROM courses
                WHERE id = ?
                """,
                (course_id,)
            ).fetchone()

    except Exception as e:

        print(
            "COURSE DETAIL ERROR:",
            e
        )

        return f"""
        <h1>COURSE DETAIL ERROR</h1>
        <pre>{e}</pre>
        """, 500

    finally:

        conn.close()

    # -------------------------
    # COURSE NOT FOUND
    # -------------------------

    if not course:

        flash(
            "Course not found.",
            "error"
        )

        return redirect(
            url_for("course")
        )

    # -------------------------
    # COURSE DETAIL PAGE
    # -------------------------

    return render_template(
        "course_detail.html",
        username=session["user_name"],
        course=course
    )


# =========================================================
# ADMIN LOGOUT
# =========================================================

@app.route("/admin/logout")
@app.route("/logout")
def logout():

    session.clear()

    flash(
        "Logged out successfully.",
        "success"
    )

    return redirect(
        url_for("home")
    )


# =========================================================
# RUN APP
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )