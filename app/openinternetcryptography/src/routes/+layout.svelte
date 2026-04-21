<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@1.0.4/css/bulma.min.css">

<!-- <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
 -->

</head>
<script lang="ts">
    import Footer from "../components/footer.svelte";
    import Hero from "../components/hero.svelte";
    import Navbar from "../components/navbar.svelte";
    import Navbar2 from "../components/navbar_2.svelte";
    import Side from "../components/side.svelte";

	let { children } = $props();

    //const store = new LazyStore('keys.json');
</script>

<Hero></Hero>
<Navbar></Navbar>
{@render children()}
<Footer></Footer>




