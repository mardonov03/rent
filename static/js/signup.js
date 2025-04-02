async function register() {
    const username = document.getElementById("username").value;
    const gmail = document.getElementById("gmail").value;
    const password = document.getElementById("password").value;

    const response = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, gmail, password })
    });

    if (response.ok) {
        document.getElementById("register-form").style.display = "none";
        document.getElementById("verify-form").style.display = "block";
    } else {
        alert("Ошибка регистрации");
    }
}

async function verify() {
    const gmail = document.getElementById("gmail").value;
    const code = document.getElementById("verification-code").value;

    const response = await fetch(`/verify/${gmail}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
    });

    if (response.ok) {
        const data = await response.json();
        localStorage.setItem("token", data.token);

        await completeRegistration();
    } else {
        alert("Неверный код");
    }
}

async function completeRegistration() {
    const username = document.getElementById("username").value;
    const gmail = document.getElementById("gmail").value;
    const password = document.getElementById("password").value;
    const token = localStorage.getItem("token");

    const response = await fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ username, gmail, password })
    });

    if (response.ok) {
        const data = await response.json();
        const token = data.token_access;

        localStorage.setItem("token", token);
        window.location.href = `/profile/${username}`;
    } else {
        alert("Ошибка завершения регистрации");
    }
}
