// static/js/app.js

// Global ephemeral storage for pattern
let selectedPattern = [];

// Shuffle array (Fisher-Yates)
function shuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

// Initialize the pattern grid
function initPatternGrid(containerId, imageCount) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = "";
  selectedPattern = [];

  let images = [];
  for (let i = 1; i <= imageCount; i++) {
    images.push(i);
  }
  images = shuffle(images);

  images.forEach(id => {
    const img = document.createElement("img");
    img.src = "images/" + id + ".png"; // Make sure these exist in static/images
    img.setAttribute("data-id", id);
    img.classList.add("pattern-image");

    // Toggle selection on click
    img.addEventListener("click", () => {
      if (!img.classList.contains("selected")) {
        img.classList.add("selected");
        selectedPattern.push(id);
      } else {
        img.classList.remove("selected");
        const idx = selectedPattern.indexOf(id);
        if (idx !== -1) {
          selectedPattern.splice(idx, 1);
        }
      }
    });
    container.appendChild(img);
  });
}

// Utility function to display messages
function displayMessage(elementId, message, isError = false) {
  const el = document.getElementById(elementId);
  if (el) {
    el.innerText = message;
    if (isError) {
      el.classList.add("error-message");
      el.classList.remove("success-message");
    } else {
      el.classList.add("success-message");
      el.classList.remove("error-message");
    }
  }
}

/* === Registration === */
const registerForm = document.getElementById("registerForm");
if (registerForm) {
  // For example, 38 images
  initPatternGrid("patternGrid", 38);

  registerForm.addEventListener("submit", async function(e) {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const email = document.getElementById("email").value;
    const pattern = selectedPattern.join("-");
    if (!username || !email || !pattern) {
      displayMessage("registerMessage", "Please fill all details and select a pattern.", true);
      return;
    }
    try {
      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, pattern })
      });
      const data = await res.json();
      if (res.ok) {
        displayMessage("registerMessage", data.message, false);
        setTimeout(() => {
          window.location.href = "login.html";
        }, 2000);
      } else {
        displayMessage("registerMessage", data.error || data.message || "Registration failed", true);
      }
    } catch (error) {
      displayMessage("registerMessage", "Error: " + error.message, true);
    }
  });
}

/* === Login === */
const loginForm = document.getElementById("loginForm");
if (loginForm) {
  // For example, 38 images
  initPatternGrid("patternGrid", 38);

  loginForm.addEventListener("submit", async function(e) {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const email = document.getElementById("email").value;
    const pattern = selectedPattern.join("-");
    if (!username || !email || !pattern) {
      displayMessage("loginMessage", "Please fill all details and select your pattern.", true);
      return;
    }
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, pattern })
      });
      const data = await res.json();
      if (res.ok) {
        displayMessage("loginMessage", data.message, false);
        setTimeout(() => {
          window.location.href = "otp.html?username=" + encodeURIComponent(username);
        }, 2000);
      } else {
        const errorMsg = data.error || data.message || "Login failed";
        displayMessage("loginMessage", errorMsg, true);

        // Lockout logic
        if (errorMsg.toLowerCase().includes("temporarily locked until")) {
          const regex = /temporarily locked until (.*)/i;
          const match = regex.exec(errorMsg);
          if (match && match[1]) {
            const lockUntilStr = match[1].trim();
            const lockUntil = new Date(lockUntilStr);
            let remainingTime = Math.ceil((lockUntil.getTime() - new Date().getTime()) / 1000);
            if (remainingTime > 0) {
              const loginBtn = document.querySelector("#loginForm button[type='submit']");
              if (loginBtn) {
                loginBtn.disabled = true;
                const intervalId = setInterval(() => {
                  remainingTime--;
                  if (remainingTime > 0) {
                    displayMessage("loginMessage", `Account locked. Please try again in ${remainingTime} seconds.`, true);
                  } else {
                    clearInterval(intervalId);
                    loginBtn.disabled = false;
                    displayMessage("loginMessage", "", false);
                  }
                }, 1000);
              }
            }
          }
        }
      }
    } catch (error) {
      displayMessage("loginMessage", "Error: " + error.message, true);
    }
  });
}

/* === OTP === */
const otpForm = document.getElementById("otpForm");
if (otpForm) {
  otpForm.addEventListener("submit", async function(e) {
    e.preventDefault();
    const urlParams = new URLSearchParams(window.location.search);
    const username = urlParams.get("username");
    const otp = document.getElementById("otp").value;
    try {
      const res = await fetch("/api/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, otp })
      });
      const data = await res.json();
      if (res.ok) {
        displayMessage("otpMessage", data.message, false);
        setTimeout(() => {
          window.location.href = "dashboard.html";
        }, 2000);
      } else {
        displayMessage("otpMessage", data.error || data.message || "OTP verification failed", true);
      }
    } catch (error) {
      displayMessage("otpMessage", "Error: " + error.message, true);
    }
  });
}

/* === Forgot Password === */
const forgotForm = document.getElementById("forgotForm");
if (forgotForm) {
  forgotForm.addEventListener("submit", async function(e) {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const email = document.getElementById("email").value;
    try {
      const res = await fetch("/api/forgot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email })
      });
      const data = await res.json();
      if (res.ok) {
        displayMessage("forgotMessage", data.message, false);
        setTimeout(() => {
          window.location.href = "login.html";
        }, 2000);
      } else {
        displayMessage("forgotMessage", data.error || data.message || "Request failed", true);
      }
    } catch (error) {
      displayMessage("forgotMessage", "Error: " + error.message, true);
    }
  });
}
