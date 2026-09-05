// LabelPro AI Academy
// Main JavaScript

document.addEventListener("DOMContentLoaded", () => {

    console.log("LabelPro AI Academy loaded successfully.");

    const courseButtons =
        document.querySelectorAll(".course-card button");

    courseButtons.forEach((button) => {

        button.addEventListener("click", () => {

            alert(
                "Course enrollment system coming soon! 🚀"
            );

        });

    });

});