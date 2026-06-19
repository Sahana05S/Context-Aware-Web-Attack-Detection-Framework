async function test() {
    const loginRes = await fetch('http://127.0.0.1:8000/api/v1/auth/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({username: 'tester99', email: 'tester99@t.com', password: 'password'})
    });
    const tokens = await loginRes.json();
    
    if (!tokens.access_token) {
        console.error("Login failed:", tokens);
        return;
    }

    const alertsRes = await fetch('http://127.0.0.1:8000/api/v1/alerts?limit=2', {
        headers: {
            'Authorization': `Bearer ${tokens.access_token}`
        }
    });

    const alerts = await alertsRes.json();
    console.log(JSON.stringify(alerts, null, 2));
}

test();
