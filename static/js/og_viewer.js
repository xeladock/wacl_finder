// Очистка конкретного текстового поля
function clearOGField(id) {
    const field = document.getElementById(id);
    if (field) {
        field.value = '';
        if (id === 'og-ip') {
            field.placeholder = 'any';
        }
    }
}

// Очистить все три поля ввода
function clearAllOGFields() {
    clearOGField('og-device');
    clearOGField('og-name');
    clearOGField('og-ip');
}

// Поиск внутри Object-Group
async function performOGSearch() {
    const device = document.getElementById('og-device').value.trim();
    const ogName = document.getElementById('og-name').value.trim();
    const ip = document.getElementById('og-ip').value.trim() || 'any';

    if (!device) {
        alert("❌ Укажите имя устройства!");
        return;
    }
    if (!ogName) {
        alert("❌ Укажите название Object-Group!");
        return;
    }

    const resultsContent = document.getElementById('og-results-content');
    resultsContent.innerHTML = '<p class="placeholder-text" style="margin-top: 80px;">Выполняется поиск в Object-Group...</p>';

    try {
        // Имитация бэкенд-запроса к вашему Python-серверу
        await new Promise(resolve => setTimeout(resolve, 800));

        resultsContent.innerHTML = `
            <pre id="og-search-pre">[РЕЗУЛЬТАТ ПОИСКА]
Устройство: ${device}
Группа: ${ogName}
Искомый IP: ${ip}

object-group network ${ogName}
 network-object host 10.20.30.40
 network-object 192.168.1.0 255.255.255.0
            </pre>
        `;
    } catch (err) {
        resultsContent.innerHTML = `<p style="color:red; text-align:center; margin-top: 80px;">Ошибка: ${err.message}</p>`;
    }
}