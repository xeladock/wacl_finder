// nat_viewer_exp.js
document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const device = urlParams.get('device');
    const lineNum = urlParams.get('line');

    if (lineNum && device) {
        loadRuleDetails(device, lineNum);
    }
});

async function loadRuleDetails(device, line) {
    try {
        // Запрос к вашему будущему (или существующему) эндпоинту деталей правила
        const response = await fetch(`/api/nat/detail?device=${encodeURIComponent(device)}&line=${line}`);
        const data = await response.json();

        if (response.ok && data.forms) {
            document.getElementById('snat-original').innerText = JSON.stringify(data.forms.pre_snat, null, 2);
            document.getElementById('snat-translated').innerText = JSON.stringify(data.forms.post_snat, null, 2);
            document.getElementById('dnat-original').innerText = JSON.stringify(data.forms.pre_dnat, null, 2);
            document.getElementById('dnat-translated').innerText = JSON.stringify(data.forms.post_dnat, null, 2);
        }
    } catch (err) {
        console.error('Ошибка при загрузке деталей правила:', err);
    }
}