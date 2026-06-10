package tlsdecoy

// defaultDecoyHTML is a minimal, plausible webpage served to non-WebSocket
// visitors and active probes. It looks like a generic SaaS landing page.
const defaultDecoyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CloudSync – Secure Data Pipeline</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
max-width:720px;margin:60px auto;padding:0 20px;color:#333;line-height:1.6}
h1{font-size:2rem;margin-bottom:.5rem}
p{color:#666}
footer{margin-top:80px;font-size:.875rem;color:#999}
</style>
</head>
<body>
<h1>CloudSync</h1>
<p>Real-time data synchronization for modern teams.</p>
<p>Please sign in to access your workspace.</p>
<footer>CloudSync Inc. All rights reserved.</footer>
</body>
</html>`
