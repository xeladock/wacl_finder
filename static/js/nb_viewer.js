document.addEventListener('DOMContentLoaded', () => {
    const inputField = document.getElementById('nb-input');
    const searchBtn = document.getElementById('nb-search-btn');
    const searchPre = document.getElementById('nb-search-pre');
    const placeholderText = document.querySelector('.nb-placeholder-text');
    const pre = document.getElementById('nb-search-pre');

// Когда приходят первые данные поиска:


    let isSearching = false;
    let abortController = null;

    searchBtn.addEventListener('click', () => {
        if (isSearching) {
            // Если уже идет поиск, кнопка работает как "Сброс / Отмена"
            stopSearch();
            return;
        }
        startSearch();
    });

    async function startSearch() {
        const text = inputField.value.trim();
        if (!text) {
            alert('Пожалуйста, введите хотя бы одну подсеть или IP-адрес.');
            return;
        }

        // Переводим интерфейс в состояние "Поиск"
        isSearching = true;
        searchBtn.textContent = 'Стоп';
        searchBtn.style.backgroundColor = '#64748b'; // Серый цвет кнопки для сброса
        inputField.disabled = true;

        if (placeholderText) placeholderText.style.display = 'none';
        searchPre.style.display = 'block';
        searchPre.style.fontStyle = 'normal'; // Гарантируем, что сам контейнер не наклонный
        searchPre.innerHTML = '🔄 <i>Запрос выполняется. Пожалуйста, подождите...</i>\n\n';

        abortController = new AbortController();

        try {
            const response = await fetch('/api/nb/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text }),
                signal: abortController.signal
            });

            if (!response.ok) {
                throw new Error(`Ошибка сервера: ${response.status}`);
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder('utf-8');
            let buffer = '';
            let isFirstChunk = true;

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n\n');
                buffer = lines.pop(); // Оставляем неполную часть в буфере

                for (const line of lines) {
                    if (!line.trim()) continue;

                    const dataLines = line.split('\n')
                        .filter(l => l.startsWith('data: '))
                        .map(l => l.replace('data: ', ''));

                    const message = dataLines.join('\n');

                    if (message === '[DONE]') {
                        stopSearch(false);
                        return;
                    }

                    if (isFirstChunk) {
                        // Очищаем сообщение "🔄 Запрос выполняется..." при получении первого результата
                        searchPre.textContent = '';
                        searchPre.style.setProperty('font-style', 'normal', 'important');
                        isFirstChunk = false;
                    }

//                     searchPre.textContent += message + '\n';
                       searchPre.innerHTML += message + '\n';
                    // Автоскролл вниз с поддержкой Firefox
                    requestAnimationFrame(() => {
                        const panel = searchPre.closest('.nb-results-panel');
                        if (panel) panel.scrollTop = panel.scrollHeight;
                    });
                }
            }
        } catch (error) {
            if (error.name === 'AbortError') {
                if (searchPre.textContent.startsWith('🔄 З')) {
                searchPre.textContent = '⛔ Поиск остановлен пользователем.\n';
                } else{
                searchPre.textContent += '\n⛔ Поиск остановлен пользователем.\n';}
            } else {
                searchPre.textContent += `\n⚠️ Произошла ошибка: ${error.message}\n`;
            }
        } finally {
            stopSearch(false);
        }
    }

    function stopSearch(shouldAbort = true) {
        if (shouldAbort && abortController) {
            abortController.abort();
        }
        isSearching = false;
        searchBtn.textContent = '🔎 Поиск';
        searchBtn.style.backgroundColor = '#2563eb';
        inputField.disabled = false;
    }
});

function downloadResult() {
    // 1. Получаем элемент ввода (замените 'nb-input' на id вашего textarea или input!)
    const inputElement = document.getElementById('nb-input') || document.querySelector('textarea');

    // 2. Получаем элемент вывода
    const preElement = document.getElementById('nb-search-pre');

    // Считываем значения (если элемент не найден, берем пустую строку)
    const inputText = inputElement ? inputElement.value.trim() : "";
    const outputText = preElement ? (preElement.innerText || preElement.textContent || "").trim() : "";

    // 3. Проверяем, есть ли хоть какие-то данные для сохранения
    if (!outputText || outputText.startsWith('⛔ П')){
            setTimeout(() => {
            alert("Нет данных для сохранения!");
        }, 30);
        return;
    }

    // 4. Формируем красивый итоговый текст с префиксами
    let fileContent = "";

    if (inputText) {
        fileContent += `---NB Viewer---\nВвод:\n${inputText}\n\n`;
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
        a.download = `acl_search_result_${timestamp}.txt`;

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