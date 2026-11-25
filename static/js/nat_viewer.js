const MIN_WIDTH = 600;
const MIN_HEIGHT = 680;

window.addEventListener('resize', () => {
    if (window.outerWidth < MIN_WIDTH || window.outerHeight < MIN_HEIGHT) {
        const targetWidth = Math.max(window.outerWidth, MIN_WIDTH);
        const targetHeight = Math.max(window.outerHeight, MIN_HEIGHT);
        window.resizeTo(targetWidth, targetHeight);
    }
});

// Очистка конкретного поля ввода
function clearNATField(id) {
    const field = document.getElementById(id);
    if (field) {
        field.value = '';
    }
}

// Защита от ввода с двоеточием в поле устройства (если пользователь скопировал строку целиком)
document.addEventListener('input', (event) => {
    if (event.target && event.target.id === 'nat-device') {
        let value = event.target.value;
        if (value.includes(':')) {
            event.target.value = value.split(':')[0].trim();
        }
    }
});

// Очистить все поля ввода на форме NAT
function clearAllNATFields() {
    clearNATField('nat-device');
    clearNATField('nat-query');

    // Сбрасываем область результатов к начальному плейсхолдеру
    const resultsContent = document.getElementById('nat-results-content');
    if (resultsContent) {
        resultsContent.innerHTML = '<p class="placeholder-text">Результаты поиска появятся здесь...</p>';
    }
}

// Функция сохранения результатов в текстовый файл
function downloadResult() {
    const deviceVal = document.getElementById('nat-device')?.value.trim() || "";
    const queryVal = document.getElementById('nat-query')?.value.trim() || "any";

    const resultsContent = document.getElementById('nat-results-content');
    const outputText = resultsContent ? (resultsContent.innerText || resultsContent.textContent || "").trim() : "";

    if (!outputText || outputText.includes("Результаты поиска появятся здесь")) {
        setTimeout(() => {
            alert("Нет данных для сохранения!");
        }, 30);
        return;
    }

    const inputLines = [`Устройство: ${deviceVal}`, `Запрос: ${queryVal}`].join('\n');
    let fileContent = "";

    if (inputLines) {
        fileContent += `---NAT Viewer---\nВвод:\n${inputLines}\n\n`;
    }

    if (outputText) {
        fileContent += `Вывод:\n${outputText}\n`;
    }

    try {
        const blob = new Blob([fileContent], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;

        const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
        a.download = `nat_search_result_${timestamp}.txt`;

        document.body.appendChild(a);
        a.click();

        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);

    } catch (err) {
        console.error("Ошибка при скачивании файла:", err);
    }
}

// Основная функция поиска правил NAT
async function performNATSearch() {
    const deviceField = document.getElementById('nat-device');
    const queryField = document.getElementById('nat-query');
    const resultsContent = document.getElementById('nat-results-content');

    const device = deviceField ? deviceField.value.trim() : "";
    const group = queryField ? queryField.value.trim() : "";

    if (!device) {
        resultsContent.innerHTML = `
            <div style="color: #ef4444; font-weight: 600; padding: 15px;">
                Ошибка: Укажите имя устройства!
            </div>
        `;
        return;
    }

    // Индикатор загрузки
    resultsContent.innerHTML = '<div class="placeholder-text">Выполняется поиск правил NAT...</div>';

    try {
        const response = await fetch('/api/nat/search', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ device, group })
        });

        const data = await response.json();

        if (!response.ok) {
            resultsContent.innerHTML = `
                <div style="color: #ef4444; font-weight: 600; padding: 15px;">
                    Ошибка: ${data.detail || 'Произошла ошибка при поиске'}
                </div>
            `;
            return;
        }

        resultsContent.innerHTML = '';

        if (!data.rules || data.rules.length === 0) {
            resultsContent.innerHTML = '<div class=><i>Совпадений не найдено.</i></div>';
            return;
        }

        // Создаем контейнер-таблицу для результатов
        const tableContainer = document.createElement('div');
        tableContainer.className = 'nat-table-container';

        // Шапка с количеством найденных правил
        const counterHeader = document.createElement('div');
        counterHeader.style.cssText = 'padding: 8px 12px; font-weight: 600; color: #475569; font-size: 13px; border-bottom: 1px solid #e2e8f0;';
        counterHeader.textContent = `Найдено трансляций: ${data.total_found}`;
        tableContainer.appendChild(counterHeader);

        // Рендерим каждое правило в виде строки / блока
        data.rules.forEach((rule, index) => {
            const ruleRow = document.createElement('div');
            ruleRow.className = 'nat-rule-item';
            ruleRow.style.cssText = 'padding: 12px; border-bottom: 1px solid #f1f5f9; display: flex; flex-direction: column; gap: 6px;';

            // Метаданные (Тип правила, строка конфига, интерфейсы)
            const metaInfo = document.createElement('div');
            metaInfo.style.cssText = 'display: flex; justify-content: space-between; font-size: 12px; color: #64748b;';
//            metaInfo.innerHTML = `
//                <span><b>#${index + 1}</b> data-line="${rule.line_number}" | Тип: <span style="color: #0284c7; font-weight: 600;">${rule.nat_type}</span></span>
//                <span>Направление: <b>${rule.real_interface || '?'}</b> ➔ <b>${rule.mapped_interface || '?'}</b></span>
//            `;
metaInfo.innerHTML = `
    <span>
        <a href="javascript:void(0);" class="rule-detail-link" data-rule-index="${index + 1}" data-line="${rule.line_number}" style="color: #2563eb; text-decoration: underline; font-weight: bold;">#${index + 1}</a>
        | Тип: <span style="color: #0284c7; font-weight: 600;">${rule.nat_type}</span>
    </span>
    <span>Направление: <b>${rule.real_interface || '?'}</b> ➔ <b>${rule.mapped_interface || '?'}</b></span>
`;

            ruleRow.appendChild(metaInfo);

            // Оригинальная строка конфига
            const preElement = document.createElement('pre');
            preElement.className = 'nat-raw-code';
            preElement.style.cssText = 'background: #f8fafc; padding: 8px 10px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #0f172a; margin: 0; white-space: pre-wrap; border: 1px solid #e2e8f0;';
            preElement.textContent = rule.raw_line;
            ruleRow.appendChild(preElement);

            tableContainer.appendChild(ruleRow);
        });

        resultsContent.appendChild(tableContainer);

    } catch (error) {
        resultsContent.innerHTML = `
            <div style="color: #ef4444; font-weight: 600; padding: 15px;">
                Ошибка: Не удалось связаться с сервером.
            </div>
        `;
        console.error('Ошибка NAT Fetch:', error);
    }
}

// Открытие окна справки
function openHelp() {
    const width = 1200;
    const height = 850;
    const left = (window.screen.width / 2) - (width / 2);
    const top = (window.screen.height / 2) - (height / 2);
    const uniqueWindowName = 'HelpViewerWindow_' + Date.now();

    window.open(
        '/help#block-2',
        uniqueWindowName,
        `width=${width},height=${height},left=${left},top=${top},resizable=yes,status=no,location=no,toolbar=no,menubar=no,scrollbars=no`
    );
}

// Горячие клавиши (Ctrl+F — поиск, Ctrl+S — сохранить, F1 — справка)
document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        performNATSearch();
    }

    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        downloadResult();
    }

    if (e.key === 'F1') {
        e.preventDefault();
        openHelp();
    }
});

// Слушаем клики внутри контейнера со списком результатов
const resultsContentEl = document.getElementById('nat-results-content');
if (resultsContentEl) {
    resultsContentEl.addEventListener('click', function(event) {
        const link = event.target.closest('.rule-detail-link');
        if (!link) return;

        event.preventDefault();

        const lineNum = link.getAttribute('data-line');
        const ruleIndex = link.getAttribute('data-rule-index');
        const deviceName = document.getElementById('nat-device')?.value.trim() || '';

        const url = `/api/nat/nat_viewer_exp.html?device=${encodeURIComponent(deviceName)}&line=${lineNum}&index=${ruleIndex}`;

        // Жесткие параметры размеров и центрирования принудительно открывают отдельное окно в Chrome/Opera
        const width = 1000;
        const height = 750;
        const left = Math.round((window.screen.width / 2) - (width / 2));
        const top = Math.round((window.screen.height / 2) - (height / 2));
        const uniqueWindowName = 'NatExpViewerWindow_' + ruleIndex + '_' + Date.now();

        const newWindow = window.open(
            url,
            uniqueWindowName,
            `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes,status=no,toolbar=no,menubar=no`
        );

        // На случай, если у пользователя в Chrome жестко включено "всегда открывать в новых вкладках"
        if (newWindow) {
            newWindow.focus();
        }
    });
}

const ruleIndex = link.getAttribute('data-rule-index'); // например, "10"
// Передаем index в параметрах URL
const url = `/api/nat/nat_viewer_exp.html?device=${encodeURIComponent(deviceName)}&line=${lineNum}&index=${ruleIndex}`;