if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () {
      navigator.serviceWorker
        .register("static/js/serviceWorker.js")
        .then(() => {})
        .catch((err) => {});
    });
  }