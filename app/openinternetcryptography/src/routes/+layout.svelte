<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@1.0.4/css/bulma.min.css">

<!-- <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
 -->
</head>
<nav class="navbar">
<div class="navbar-brand">
    <button class="button is-warning">OpenInternetCryptography</button>
</div>
    <div class="navbar-item">
	    <a class="navbar-item" href="/home">Home</a>
    </div>
    <div class="navbar-item">
        <a class="navbar-item" href="/keys">Keys</a>
    </div>
    <div class="navbar-item">
        <a class="navbar-item" href="/settings">Digital Signing</a>
    </div>
    <div class="navbar-item">
        <a class="navbar-item" href="/encrypt">Encrypt Data</a>
    </div>
    <div class="navbar-item">
        <a class="navbar-item" href="/certs">Certificates</a>
    </div>
	
    <div class="navbar-item">
    <a class="navbar-item navbar-link">Advanced     
    </a>
    </div>
    <div class="navbar-end">
        <a class="navbar-item navbar-link">Identity</a>
    </div>
</nav>

<script>
	let { children } = $props();
</script>

{@render children()}
