    function fitNatViewerToScreen() {
    const vh = window.innerHeight;
    const boxes = document.querySelectorAll('.nat-sub-box');

    // Проверяем, запущен ли сайт в Firefox
    const isFirefox = navigator.userAgent.toLowerCase().includes('firefox');

    // Для Firefox делаем чуть больший вычет, чтобы компенсировать его расчет рамок
    const offset = isFirefox ? 249 : 227;

    // Считаем высоту под конкретный браузер
    const availableHeight = vh - offset;
    const boxHeight = Math.floor(availableHeight / 2) - 50; // минусуем заголовки секций

    boxes.forEach(box => {
        box.style.height = Math.max(120, boxHeight) + 'px';
    });
}

    // Запускаем при загрузке и при любом изменении/разворачивании окна
    window.addEventListener('load', () => {
        setTimeout(fitNatViewerToScreen, 50);
    });
    window.addEventListener('resize', fitNatViewerToScreen);