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
        '/help',
        uniqueWindowName,
        `width=${width},height=${height},left=${left},top=${top},resizable=yes,status=no,location=no,toolbar=no,menubar=no,scrollbars=no`
    );
}

function openOgViewer() {
    // Рассчитываем координаты, чтобы окно открылось ровно по центру экрана
    const width = 680;
    const height = 730;
    const left = (window.screen.width / 2) - (width / 2);
    const top = (window.screen.height / 2) - (height / 2);
    const uniqueWindowName = 'OGViewerWindow_' + Date.now();

    // Открываем окно в режиме pop-up с заданными размерами
    window.open(
        '/og-viewer',
       /* 'OGViewerWindow',*/
       uniqueWindowName,
        `width=${width},height=${height},left=${left},top=${top},resizable=yes,status=no,location=no,toolbar=no,menubar=no,scrollbars=no`
    );
}


 
    function openNbViewer() {
        const width = 980;
        const height = 780;
        const left = (window.screen.width / 2) - (width / 2);
        const top = (window.screen.height / 2) - (height / 2);
        const uniqueWindowName = 'NBViewerWindow_' + Date.now();

        window.open(
            '/nb-viewer',
            uniqueWindowName,
            `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=no`
        );
    }

        function resetIPs() {
            const src = document.getElementById('source_ip');
            const dst = document.getElementById('dest_ip');

            src.value = '';
            dst.value = '';

            src.placeholder = 'any';
            dst.placeholder = 'any';
        }

        function reverseIPs() {
            const source = document.getElementById('source_ip');
            const dest = document.getElementById('dest_ip');
            const temp = source.value;
            source.value = dest.value;
            dest.value = temp;
        }



document.addEventListener('keydown', function(e) {
if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        performSearch();
    }
if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        downloadResult();
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'r') {
        e.preventDefault();
        resetIPs();
    }
if (e.key === 'F1') {
        e.preventDefault(); // Блокируем стандартную справку браузера/ОС
        openHelp();
        }

    });

        document.addEventListener('DOMContentLoaded', function() {

        // Логика для регионов
        const allRegions = document.getElementById('all-regions');
        if (allRegions) {
            allRegions.addEventListener('change', function() {
                const isChecked = this.checked;
                const checkboxes = document.querySelectorAll('#regions-group .region-cb');
                checkboxes.forEach(cb => cb.checked = isChecked);
            });
        }

        // Логика для вендоров
        const allVendors = document.getElementById('all-vendors');
        if (allVendors) {
            allVendors.addEventListener('change', function() {
                const isChecked = this.checked;
                const checkboxes = document.querySelectorAll('#vendor-group .vendor-cb');
                checkboxes.forEach(cb => cb.checked = isChecked);
            });
        }
        });
 

    let isSearching = false;
    let abortController = null;

// Единый обработчик для кнопки
async function handleSearchClick() {
    if (isSearching) {
        stopSearch();
        return;
    }
    await performSearch();
}

// Функция сброса/остановки поиска
function stopSearch(shouldAbort = true) {
    if (shouldAbort && abortController) {
        abortController.abort();
    }

    isSearching = false;
    abortController = null;


    // Возвращаем кнопку в исходный вид

    // Укажите ваш ID кнопки
    const searchBtn = document.getElementById('search-btn');
    const saveBtn = document.getElementById('save-btn');

    if (searchBtn) {
        searchBtn.textContent = '🔎 Поиск';
        searchBtn.style.backgroundColor = ''; // Сброс цвета из inline-стилей
    }

    // 3. Возвращаем кнопку сохранения в исходное состояние
    if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.classList.remove('disabled'); // Был написано 'enable', исправлено на 'disabled'
        saveBtn.style.backgroundColor = '';
    }

    // Включаем обратно IP-поля
    const srcInput = document.getElementById('source_ip');
    const dstInput = document.getElementById('dest_ip');

    if (srcInput) {
    srcInput.disabled = false;
    srcInput.style.backgroundColor = '';
}
    if (dstInput) {
    dstInput.disabled = false;
    dstInput.style.backgroundColor = '';
    }

}

async function performSearch() {
    const resultsDiv = document.getElementById('results-content');
    const searchBtn = document.getElementById('search-btn'); // Укажите ваш ID кнопки
    const srcInput = document.getElementById('source_ip');
    const dstInput = document.getElementById('dest_ip');


    // === ВАЛИДАЦИЯ ЧЕКБОКСОВ И ИП ===
    const uesChecked = document.querySelectorAll('#ues-group input[type="checkbox"]:checked').length;
    if (uesChecked === 0) {
        alert("❌ Нужно выбрать хотя бы один УЭС!");
        return;
    }

    const ues = [];
    document.querySelectorAll('#ues-group input[type="checkbox"]:checked').forEach(cb => {
        ues.push(cb.parentElement.textContent.trim());
    });

    const regions = [];
    document.querySelectorAll('#regions-group input[type="checkbox"]:checked').forEach(cb => {
        regions.push(cb.parentElement.textContent.trim());
    });
    const regionsChecked = document.querySelectorAll('#regions-group input[type="checkbox"]:checked').length;
    if (regionsChecked === 0) {
        alert("❌ Нужно выбрать хотя бы один регион!");
        return;
    }

    const vendors = [];
    document.querySelectorAll('#vendor-group input[type="checkbox"]:checked').forEach(cb => {
        vendors.push(cb.parentElement.textContent.trim());
    });
    const vendorsChecked = document.querySelectorAll('#vendor-group input[type="checkbox"]:checked').length;
    if (vendorsChecked === 0) {
        alert("❌ Нужно выбрать хотя бы одну платформу!");
        return;
    }

    const srcValue = srcInput.value.trim();
    const dstValue = dstInput.value.trim();
    const sorMode = document.getElementById('source_or_dest').checked;

    if (sorMode) {
        const srcFilled = srcValue && srcValue !== 'any';
        const dstFilled = dstValue && dstValue !== 'any';

        if (srcFilled && dstFilled) {
            alert("❌ В режиме 'Source or Destination' должен быть заполнен только один IP-адрес!");
            return;
        }
        if (!srcFilled && !dstFilled) {
            alert("❌ В режиме 'Source or Destination' нужно заполнить хотя бы один IP-адрес!");
            return;
        }
    }

    const data = {
        source_ip: srcValue || 'any',
        dest_ip: dstValue || 'any',
        strict_mode: document.getElementById('strict_match').checked,
        sod: document.getElementById('source_or_dest').checked,
        ues: ues,
        regions: regions,
        vendors: vendors
    };

    if (!isValidIPorNetwork(data.source_ip)) {
        alert("❌ Неверный формат Source IP: " + data.source_ip + "\n\nДолжен быть IP-адрес или сеть (например 10.0.0.0/8)/");
        return;
    }

    if (!isValidIPorNetwork(data.dest_ip)) {
        alert("❌ Неверный формат Destination IP: " + data.dest_ip + "\n\nДолжен быть IP-адрес или сеть (например 10.0.0.0/8)/");
        return;
    }



    // === ПЕРЕВОДИМ ИНТЕРФЕЙС В СОСТОЯНИЕ "ПОИСК" ===
    isSearching = true;
    abortController = new AbortController();

//112//

    if (searchBtn) {
        const saveBtn = document.getElementById('save-btn');
        searchBtn.textContent = 'Стоп';
        searchBtn.style.backgroundColor = '#64748b'; // Серый цвет при поиске
        saveBtn.disabled = true;
        saveBtn.classList.add('disabled');
        saveBtn.style.backgroundColor = '#64748b';

    }

    if (srcInput) {
        srcInput.disabled = true;
        srcInput.style.backgroundColor = '#e2e8f0'; // Серый цвет для disabled полей
    }
    if (dstInput) {
        dstInput.disabled = true;
        dstInput.style.backgroundColor = '#e2e8f0'; // Серый цвет для disabled полей
    }

    resultsDiv.innerHTML = '<p class="placeholder-text">Выполняется поиск...</p>';
    await new Promise(resolve => setTimeout(resolve, 500));  // ← задержка

    if (!isSearching) {
        resultsDiv.innerHTML = ''; // Очищаем поле вывода
        return;

    }
    try {
        // Передаем signal для возможности отмены
        const response = await fetch('/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
            signal: abortController.signal
        });

    // 1. Если бэкенд сообщил, что сервис недоступен (503) — перезагружаем страницу!
        if (response.status === 503) {
            window.location.reload(); // FastAPI при перезагрузке сам отдаст get_error_html()
            return;
        }

        if (!response.ok) {
            resultsDiv.innerHTML = `<p style="color:red; padding:15px;">Ошибка сервера: ${response.statusText}</p>`;
            return;
        }

        resultsDiv.style.paddingRight = "0";
        resultsDiv.style.paddingTop = "0";
        resultsDiv.style.paddingBottom = "0";

        resultsDiv.innerHTML = `<pre id="search-pre" style="
            background: #ffffff;
            padding: 1px;
            margin: 0px !important;
            width: 100%;
            box-sizing: border-box;
            max-height: calc(100vh - 300px);
            overflow: auto;
            white-space: pre;
            border-radius: 6px 0 0 6px;
            content-visibility: auto;
            contain-intrinsic-size: 100px 10000px;
        "></pre>`;

        const preElement = document.getElementById('search-pre');
        const reader = response.body.getReader();
        const decoder = new TextDecoder("utf-8");

        let textBuffer = "";
        let isScrollPending = false;

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;

            textBuffer += decoder.decode(value, { stream: true });
            const endsWithNewline = textBuffer.endsWith("\n");
            const lines = textBuffer.split("\n");

            if (endsWithNewline) {
                lines.pop();
                textBuffer = "";
            } else {
                textBuffer = lines.pop();
            }

            if (lines[0] !== undefined) {
                const readyText = lines.join("\n") + "\n";
                preElement.insertAdjacentText('beforeend', readyText);

                if (!isScrollPending) {
                    isScrollPending = true;
                    requestAnimationFrame(() => {
                        preElement.scrollTop = preElement.scrollHeight;
                        isScrollPending = false;
                    });
                }
            }
        }

        if (textBuffer && textBuffer.trim()) {
            const cleanText = textBuffer.replace("~~~", "");
            preElement.insertAdjacentText('beforeend', cleanText);
        }

        requestAnimationFrame(() => {
            if (preElement) preElement.scrollTop = preElement.scrollHeight;
        });

    } catch (err) {
        const preElement = document.getElementById('search-pre');

        if (err.name === 'AbortError') {
            // Если поиск был остановлен уже ПОСЛЕ отправки сетевого запроса
            const stopMsg = '⛔ Поиск остановлен пользователем.\n\n';
            if (preElement) {
                preElement.insertAdjacentText('beforeend', `\n${stopMsg}`);
                preElement.scrollTop = preElement.scrollHeight;
            } else {
                resultsDiv.innerHTML = ''; // Или оставляем пустым, если нужно: resultsDiv.innerHTML = '';
            }
        } else {
            // При ошибке сети или сервера
            resultsDiv.innerHTML = `<p style="color:red; padding:15px;">Ошибка соединения: ${err.message}</p>`;
        }
    } finally {
        // Возвращаем интерфейс в обычное состояние после завершения или ошибки
        stopSearch(false);
    }
}
     
  
function isValidIPorNetwork(str) {
        if (str === 'any') return true;

        // Простая проверка IPv4 / CIDR
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
        if (!ipPattern.test(str)) return false;

        const parts = str.split('/');
        const ip = parts[0].split('.');

        for (let num of ip) {
            const n = parseInt(num);
            if (n < 0 || n > 255) return false;
        }

        if (parts.length === 2) {
            const mask = parseInt(parts[1]);
            if (mask < 0 || mask > 32) return false;
        }

    return true;
}
       
function downloadResult() {
    const saveBtn = document.getElementById('save-btn');

        // Если кнопка заблокирована — игнорируем вызов (в том числе по Ctrl+S)
        if (saveBtn && saveBtn.disabled) {
            return;
        }
        const resultsDiv = document.getElementById('results-content');
        const pre = resultsDiv.querySelector('pre');

    if (!pre || !pre.textContent.trim()) {
            setTimeout(() => {
                alert("Нет данных для сохранения!");
            }, 30);

            return;
        }

        const text = pre.textContent || pre.innerText;
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `acl_search_result_${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
   
