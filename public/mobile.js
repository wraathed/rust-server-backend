document.addEventListener('DOMContentLoaded', () => {
    const menuToggle = document.querySelector('.menu-toggle');
    const nav = document.querySelector('nav');

    if (menuToggle && nav) {
        menuToggle.addEventListener('click', () => {
            nav.classList.toggle('active');
            
            // Animation for the hamburger lines (Optional cool effect)
            const spans = menuToggle.querySelectorAll('span');
            if (nav.classList.contains('active')) {
                // Turn into X
                spans[0].style.transform = "rotate(45deg) translate(5px, 6px)";
                spans[1].style.opacity = "0";
                spans[2].style.transform = "rotate(-45deg) translate(5px, -6px)";
            } else {
                // Back to Hamburger
                spans[0].style.transform = "none";
                spans[1].style.opacity = "1";
                spans[2].style.transform = "none";
            }
        });
    }
});