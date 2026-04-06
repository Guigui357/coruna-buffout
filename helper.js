function postLog(message) {
    (async () => {
        try {
            const response = await fetch('/log', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message })
            });
        } catch (err) {
            console.error("Failed to post log:", err);
        }
    })();
}

function log(string) {
    document.getElementById('status').innerHTML += '<p style="margin: 0; font-family: Menlo; word-break: break-all; font-size: 22px; text-align: left">' + string + '</p>';
    postLog(string);
}
