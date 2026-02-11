document.addEventListener("DOMContentLoaded", () => {
    // 1. Inject Loader HTML
    const loaderHTML = `
        <div class="loader-bar" id="loader-bar"></div>
        <div id="page-loader">
            <div class="loader-spinner"></div>
        </div>
    `;
    document.body.insertAdjacentHTML('afterbegin', loaderHTML);

    const loader = document.getElementById('page-loader'); // The black background + spinner
    const bar = document.getElementById('loader-bar');    // The orange line

    // 2. Start Animation (Simulates loading)
    function startLoading() {
        // Reset state for new navigation
        bar.classList.remove('bar-hidden');
        loader.classList.remove('loader-hidden');
        
        // Start progress
        setTimeout(() => { bar.style.width = "30%"; }, 50);
        setTimeout(() => { bar.style.width = "70%"; }, 500);
    }

    // 3. Finish Animation (Page Loaded)
    function finishLoading() {
        // Push to 100%
        bar.style.width = "100%";
        
        // Fade out the black background immediately
        loader.classList.add('loader-hidden');

        // Wait a moment for the bar to hit 100%, then fade it out using Opacity
        setTimeout(() => {
            bar.classList.add('bar-hidden');
        }, 500); 
    }

    // Run when page is fully loaded
    window.addEventListener('load', finishLoading);

    // Intercept Links
    document.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', (e) => {
            const href = link.getAttribute('href');
            if (!href || href.startsWith('#') || href.startsWith('javascript') || link.target === '_blank') return;
            
            // Start the loader visual immediately
            startLoading();
        });
    });
});