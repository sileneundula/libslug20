<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@1.0.4/css/bulma.min.css">

<!-- <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
 -->

</head>
<script lang="ts">
	let { children } = $props();
</script>

<div id="hero">
<div class="hero-body section">
    <h1 class="title">OpenInternetCryptography</h1>
    <h2 class="subtitle">This program contains functionality for the Open Internet Project.<br><i>OpenInternetId:</i> <br> <i>Current-Identity:</i> <br>  </h2>
    <!-- Add For Current Identity Username and Key Checksum -->
</div>
</div>
<section class="section">
<nav class="navbar">
<div class="navbar-brand">
    <a class="navbar-item">Liberatø⨎</a>
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
    <div class="navbar-item has-dropdown is-hoverable">
        <a id="oint-identity" class="navbar-link">Identity</a>
        <div class="navbar-dropdown">
        <a class="navbar-item">
            Switch Accounts
        </a>
        <a class="navbar-item">
            Add Account
        </a>
        </div>
        </div>
        <!-- Add Up To 8 accounts -->
    </div>
</nav>
</section>
<footer class="footer">
<div class="content has-text-centered">
<p><b>OpenInternetCryptography</b> from Liberatø⨎&#123;&#125; Suite | Built by "SundialSource" Under WeSpeakInCursive.xyz</p>
</div>
</footer>




{@render children()}