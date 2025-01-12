document.addEventListener("DOMContentLoaded", function() {
    const rideNames = document.querySelectorAll('.ride-name');

    rideNames.forEach(function(ride) {
        // If the browser doesn't support line-clamp (Webkit-based browsers)
        if (!CSS.supports('display', '-webkit-box')) {
            let textContent = ride.textContent.trim();

            // Truncate the text to 100 characters
            if (textContent.length > 100) {
                ride.textContent = textContent.substring(0, 100) + '...';
            }
        }
    });
});