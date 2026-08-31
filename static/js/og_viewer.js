        const MIN_WIDTH = 600;
        const MIN_HEIGHT = 680;

        window.addEventListener('resize', () => {
            // Проверяем текущие внешние размеры окна (включая рамки браузера)
            if (window.outerWidth < MIN_WIDTH || window.outerHeight < MIN_HEIGHT) {

                // Вычисляем новые размеры (не даем им упасть ниже лимита)
                const targetWidth = Math.max(window.outerWidth, MIN_WIDTH);
                const targetHeight = Math.max(window.outerHeight, MIN_HEIGHT);

                // Принудительно меняем размер окна обратно
                window.resizeTo(targetWidth, targetHeight);
            }
        });

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

const deviceField = document.getElementById('og-device');
document.addEventListener('input', (event) => {
    // Проверяем, что ввод происходит именно в поле устройства (укажите ваш ID)
    if (event.target && event.target.id === 'og-device') {
        let value = event.target.value;

        // Если есть двоеточие — отрезаем всё после него
        if (value.includes(':')) {
            event.target.value = value.split(':')[0].trim();
        }
    }
});

// Очистить все три поля ввода
function clearAllOGFields() {
    clearOGField('og-device');
    clearOGField('og-name');
    clearOGField('og-ip');
}

function downloadResult() {
    // 1. Получаем элемент ввода (замените 'og-input' на id вашего textarea или input!)
    const deviceVal = document.getElementById('og-device')?.value.trim() || "";
    const nameVal = document.getElementById('og-name')?.value.trim() || "";
    let ipVal = document.getElementById('og-ip')?.value.trim() || "";

    // Если IP не введен — выводим 'any', как в placeholder
    if (!ipVal) {
        ipVal = "any";
    }



    // 2. Получаем элемент вывода результатов
    const preElement = document.getElementById('og-search-pre');
    const outputText = preElement ? (preElement.innerText || preElement.textContent || "").trim() : "";

    // 3. Проверяем, есть ли хоть какие-то данные для сохранения
    if (!outputText) {
        setTimeout(() => {
            alert("Нет данных для сохранения!");
        }, 30);
        return;
    }

    const inputLines = [deviceVal, nameVal, ipVal].join('\n');
    // 4. Формируем красивый итоговый текст с префиксами
    let fileContent = "";

    if (inputLines) {
        fileContent += `---OG Viewer---\nВвод:\n${inputLines}\n\n`;
    }

    if (outputText) {
        fileContent += `Вывод:\n${outputText}\n`;
    }

    // 5. Создаем Blob и скачиваем файл
    try {
        const blob = new Blob([fileContent], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;

        // Формируем имя файла с текущей датой и временем
        const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
        a.download = `og_search_result_${timestamp}.txt`;

        document.body.appendChild(a);
        a.click();

        // Очищаем ссылку из памяти
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);

    } catch (err) {
        console.error("Ошибка при скачивании файла:", err);
    }
}



// Поиск внутри Object-Group
async function performOGSearch() {
    console.log("Кнопка 'Поиск' в OG Viewer успешно нажата!");

    // Получаем элементы из вашей HTML-верстки по правильным ID
    const deviceField = document.getElementById('og-device');
    if (deviceField) {
        deviceField.addEventListener('input', (event) => {
            let value = event.target.value;

            // Если в строке есть двоеточие
            if (value.includes(':')) {
                // Отрезаем всё, начиная с двоеточия, и убираем лишние пробелы по краям
                value = value.split(':')[0].trim();

                // Обновляем значение прямо в поле ввода
                event.target.value = value;
            }
        });
    }

    const groupField = document.getElementById('og-name');
    const ipField = document.getElementById('og-ip');
    const resultsContent = document.getElementById('og-results-content');



    // Проверяем, что JS видит элементы на странице
    if (!deviceField || !groupField || !ipField || !resultsContent) {
        console.error("Ошибка: Одно из полей или панель результатов не найдены в HTML!");
        return;
    }

    const device = deviceField.value.trim();
    const group = groupField.value.trim();
    const ip = ipField.value.trim();

    console.log("Данные из полей:", { device, group, ip });

    // Показываем индикатор загрузки
    resultsContent.innerHTML = '<div class="placeholder-text">Выполняется поиск...</div>';

    try {
        // Запрос идет на наш роутер FastAPI в файле og_viewer.py
        const response = await fetch('/api/og/search', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ device, group, ip })
        });

        const data = await response.json();

        // Обрабатываем ошибки валидации от сервера
        if (!response.ok) {
            resultsContent.innerHTML = `
                <div style="color: #ef4444; font-weight: 600; padding: 15px;">
                    Ошибка: ${data.detail || 'Произошла ошибка при поиске'}
                </div>
            `;
            return;
        }

        // Очищаем панель и выводим реальные данные
        resultsContent.innerHTML = '';

        const preElement = document.createElement('pre');
        preElement.id = 'og-search-pre';

        // Бежим по массиву результатов из Python-парсера
        data.results.forEach(item => {
            const span = document.createElement('span');
            span.textContent = item.text + '\n';

            // Если элемент — это совпавший IP, делаем его жирным
            if (item.bold) {
                span.style.setProperty('font-weight', 'bold', 'important');
    // Принудительно красим в зеленый с наивысшим приоритетом
                span.style.setProperty('color', '#10b981', 'important');
            }

            if (item.italic) {
                span.style.setProperty('font-style', 'italic', 'important');
                span.style.setProperty('color', 'black', 'important');
            }

            if (item.empty) {
                span.style.setProperty('font-style', 'italic', 'important');
                span.style.setProperty('color', 'black', 'important');
            }

            preElement.appendChild(span);
        });

        resultsContent.appendChild(preElement);

    } catch (error) {
        resultsContent.innerHTML = `
            <div style="color: #ef4444; font-weight: 600; padding: 15px;">
                Ошибка: Не удалось связаться с сервером.
            </div>
        `;
        console.error('Ошибка OG Fetch:', error);
    }
}

function openHelp() {
        // Открывает страницу справки в новой вкладке

    const width =1200;
    const height = 850;

    // Высчитываем координаты для центрирования окна
    const left = (window.screen.width / 2) - (width / 2);
    const top = (window.screen.height / 2) - (height / 2);

    const uniqueWindowName = 'HelpViewerWindow_' + Date.now();

    // Открываем окно всплывающим pop-up
    window.open(
        '/help#block-2',
        uniqueWindowName,
        `width=${width},height=${height},left=${left},top=${top},resizable=yes,status=no,location=no,toolbar=no,menubar=no,scrollbars=no`
    );
}
document.addEventListener('keydown', function(e) {
if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        performOGSearch();
    }

if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        downloadResult();

    }
if (e.key === 'F1') {
        e.preventDefault(); // Блокируем стандартную справку браузера/ОС
        openHelp();
        }

    });