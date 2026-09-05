
const completeBtn = document.querySelector(".complete-btn");
const progressFill = document.querySelector(".progress-fill");
const progressText = document.querySelector(".progress-title span");

let progress = 35;

completeBtn.addEventListener("click", () => {

    if(progress < 100){

        progress += 5;

        progressFill.style.width = progress + "%";
        progressText.innerText = progress + "%";

        completeBtn.innerHTML = "🎉 Lesson Completed";

        setTimeout(()=>{
            completeBtn.innerHTML = "✅ Mark Lesson Complete";
        },1500);

    }

});

document.querySelectorAll(".lesson").forEach(item=>{

    item.addEventListener("click",()=>{

        if(item.classList.contains("locked")){

            alert("🔒 This lesson will unlock after completing previous lessons.");

            return;
        }

        document.querySelectorAll(".lesson").forEach(l=>l.classList.remove("active"));

        item.classList.add("active");

    });

});

document.querySelector(".download-btn").onclick=()=>{
    alert("📄 PDF Notes download feature will be connected next.");
}

document.querySelector(".dataset-btn").onclick=()=>{
    alert("📦 Practice dataset will be available soon.");
}