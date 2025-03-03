document.addEventListener("DOMContentLoaded", function () {
    let maliciousURLCount = 0;
    let maliciousAttachmentCount = 0;

    // Apply Color-Coded Indicators for URLs
    document.querySelectorAll("#url-section .list-group-item").forEach((item, index) => {
        let maliciousCount = parseInt(item.querySelector("strong:nth-child(4)").textContent.split(": ")[1]);
        let badge = document.getElementById(`url-status-${index}`);

        if (maliciousCount > 10) {
            badge.textContent = "❌ Malicious";
            badge.classList.add("bg-danger", "text-white");
            maliciousURLCount++;
        } else if (maliciousCount > 5) {
            badge.textContent = "⚠️ Suspicious";
            badge.classList.add("bg-warning", "text-dark");
        } else {
            badge.textContent = "✅ Safe";
            badge.classList.add("bg-success", "text-white");
        }
    });

    // Apply Color-Coded Indicators for Attachments
    document.querySelectorAll("#attachment-section .list-group-item").forEach((item, index) => {
        let maliciousCount = parseInt(item.querySelector("strong:nth-child(4)").textContent.split(": ")[1]);
        let badge = document.getElementById(`attachment-status-${index}`);

        if (maliciousCount > 0) {
            badge.textContent = "❌ Malicious";
            badge.classList.add("bg-danger", "text-white");
            maliciousAttachmentCount++;
        } else {
            badge.textContent = "✅ Safe";
            badge.classList.add("bg-success", "text-white");
        }
    });

    // Update Summary Section
    document.getElementById("malicious-url-count").textContent = maliciousURLCount;
    document.getElementById("malicious-attachment-count").textContent = maliciousAttachmentCount;
});

// Generate CSV Report
function downloadCSV() {
    window.location.href = "/generate_csv/";
}
