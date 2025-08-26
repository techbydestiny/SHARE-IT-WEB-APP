
var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
  return new bootstrap.Tooltip(tooltipTriggerEl)
})
const imageInput = document.getElementById('imageUpload');

imageInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file && file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const image = document.querySelector('.upload-image');
            image.src = e.target.result;
        };
        reader.readAsDataURL(file);
    } else {
        alert('Please upload a valid image file.');
    }
});
function copyShareLink(link) {
    navigator.clipboard.writeText(link).then(() => {
        alert("Link copied to clipboard!");
    }).catch(err => {
        console.error("Error copying: ", err);
    });
}


function downloadMessageImage(elementId) {
    const element = document.getElementById(elementId);

    html2canvas(element, { scale: 2 }).then(canvas => {
        const link = document.createElement("a");
        link.download = "message.png";  // File name
        link.href = canvas.toDataURL("image/png");
        link.click();
    });
}