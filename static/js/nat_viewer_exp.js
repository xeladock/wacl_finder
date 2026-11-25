document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const device = urlParams.get('device');
    const lineNum = urlParams.get('line');
    const ruleIndex = urlParams.get('index'); // Считываем номер правила (например, "10")

    // Динамически меняем заголовок, если передан индекс
    if (ruleIndex) {
        const titleElement = document.getElementById('page-title');
        if (titleElement) {
            titleElement.innerHTML = `🔀 NAT Rule #${ruleIndex} Details`;
        }
    }

    if (lineNum && device) {
        loadRuleDetails(device, lineNum);
    }
});

// nat_viewer_exp.j

async function loadRuleDetails(device, line) {
    try {
        const response = await fetch(`/api/nat/detail?device=${encodeURIComponent(device)}&line=${line}`);
        const data = await response.json();

        if (response.ok && data.forms) {
            // Выводим текст напрямую, без JSON.stringify
            document.getElementById('snat-original').innerText = data.forms.pre_snat || '';
            document.getElementById('snat-translated').innerText = data.forms.post_snat || '';
            document.getElementById('dnat-original').innerText = data.forms.pre_dnat || '';
            document.getElementById('dnat-translated').innerText = data.forms.post_dnat || '';
        }
    } catch (err) {
        console.error('Ошибка при загрузке деталей правила:', err);
    }
}