document.addEventListener('DOMContentLoaded', () => {
    const inputField = document.getElementById('nb-input');
    const searchBtn = document.getElementById('nb-search-btn');
    const searchPre = document.getElementById('nb-search-pre');
    const placeholderText = document.querySelector('.nb-placeholder-text');
    const pre = document.getElementById('nb-search-pre');

// Когда приходят первые данные поиска:
    if (placeholder) placeholder.style.display = 'none'; // Скрываем плейсхолдер
    pre.style.display = 'block';                        // Показываем <pre>
    pre.textContent += newChunkOfData;

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
                searchPre.textContent += '\n⛔ Поиск остановлен пользователем.\n';
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