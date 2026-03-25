<section class="section">
<h1 class="title">Liberatø⨎&#123;Identity-Generation&#125;</h1>
<p class="subtitle">This is the initial generation of an identity for the liberato ecosystem and other connected entities. It involves generating keypairs for identity and syncing it with the network.</p>
<br>
<div class="field">
<h1 class="title is-4">Local Account Information</h1>
<label class="label">Enter an Identity Username (this is only known to you for your profile's identity identifier): </label>
<input class="input" type="text" placeholder="Liberatø⨎&#123; &#125; - Identity Local Name" />
<br>
<br>
<button id="generate-username" class="button is-small">Generate Username</button>
<br>
<br>
<label class="label">Write a description for your identity</label>
<input class="input" type="text" placeholder="Liberatø⨎&#123; &#125; - Description (optional)" />
<hr>
<h1 class="title is-4">Cryptography Settings</h1>
<label class="label">Networks Interoperable With:</label>
<div class="checkboxes">
    <label class="checkbox">
    <input type="checkbox" class="is-primary" checked readonly disabled/>
    Liberatø Web 3.20
  </label>
      <label class="checkbox">
    <input type="checkbox" checked readonly disabled />
    SumatraChain
  </label>
      <label class="checkbox">
    <input type="checkbox" />
    Ethereum (Liberatø Extension)
  </label>
</div>
<br>
<label class="label">Keypair Algorithm:</label>
<div id="keypair-algorithm" class="select">
  <select>
    <option>ShulginSigning (SPHINCS+ and ED25519)</option>
    <option>EsphandSigning (FALCON1024 and ED25519)</option>
    <option>AbsolveSigning (ML-DSA and ED25519)</option>
  </select>
</div>
</div>
<hr>
<button id="create-identity" class="button is-primary is-large">Generate Account</button>
</section>
    