let currentObjectUrl = null;
const previewContainer = document.getElementById('preview-container');
const defaultText = document.getElementById('default-text');

// Elements to toggle
const img = document.getElementById('preview-img');
const fileCard = document.getElementById('file-preview-card');
const extensionBadge = document.getElementById('file-extension');

const nameSpan = document.getElementById('file-name');
const trashBtn = document.getElementById('trashBtn');
const fileInput = document.getElementById('fileInput');

function handleFileSelect(input) {
    const file = input.files[0];
    if (file) {
        if (currentObjectUrl) { URL.revokeObjectURL(currentObjectUrl); }
        
        // UI State: Show Preview, Hide Default Text
        defaultText.style.display = 'none';
        previewContainer.style.display = 'flex';
        trashBtn.style.display = 'flex';
        nameSpan.textContent = file.name;

        // Logic: Is it an image?
        if (file.type.startsWith('image/')) {
            img.style.display = 'block';
            fileCard.style.display = 'none';
            
            currentObjectUrl = URL.createObjectURL(file);
            img.src = currentObjectUrl;
        } else {
            img.style.display = 'none';
            fileCard.style.display = 'flex';
            
            const ext = file.name.split('.').pop() || 'FILE';
            extensionBadge.textContent = ext.toUpperCase();
        }
    }
}

function clearFile(event) {
    event.preventDefault(); 
    event.stopPropagation();
    
    fileInput.value = '';
    if (currentObjectUrl) {
        URL.revokeObjectURL(currentObjectUrl);
        currentObjectUrl = null;
    }
    img.src = '';

    // Reset UI
    previewContainer.style.display = 'none';
    trashBtn.style.display = 'none';
    defaultText.style.display = 'flex';
}