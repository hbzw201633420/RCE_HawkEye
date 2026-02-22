package web

var loginHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RCE HawkEye - Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        html, body {
            height: 100%;
            width: 100%;
        }
        
        body {
            font-family: 'Fira Sans', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .lang-selector {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 100;
        }
        
        .lang-selector select {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(248, 250, 252, 0.1);
            border-radius: 8px;
            padding: 10px 16px;
            color: #f8fafc;
            cursor: pointer;
            font-size: 14px;
            font-family: 'Fira Sans', sans-serif;
            transition: all 0.2s ease;
        }
        
        .lang-selector select:hover {
            border-color: #22C55E;
        }
        
        .login-card {
            width: 100%;
            max-width: 420px;
            padding: 48px 40px;
            background: rgba(30, 41, 59, 0.9);
            backdrop-filter: blur(20px);
            border-radius: 24px;
            border: 1px solid rgba(248, 250, 252, 0.1);
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        
        .login-logo {
            text-align: center;
            margin-bottom: 40px;
        }
        
        .login-logo svg {
            width: 72px;
            height: 72px;
            color: #22C55E;
            margin-bottom: 20px;
        }
        
        .login-logo h1 {
            font-size: 32px;
            font-weight: 700;
            color: #f8fafc;
            margin: 0 0 10px 0;
            letter-spacing: -0.5px;
        }
        
        .login-logo p {
            color: rgba(248, 250, 252, 0.6);
            margin: 0;
            font-size: 15px;
        }
        
        .login-form .form-group {
            margin-bottom: 24px;
        }
        
        .login-form label {
            display: block;
            margin-bottom: 10px;
            color: rgba(248, 250, 252, 0.8);
            font-size: 14px;
            font-weight: 500;
        }
        
        .input-icon-wrapper {
            position: relative;
        }
        
        .input-icon-wrapper svg {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            width: 20px;
            height: 20px;
            color: rgba(248, 250, 252, 0.4);
            pointer-events: none;
        }
        
        .input-icon-wrapper input {
            width: 100%;
            padding: 14px 16px 14px 48px;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(248, 250, 252, 0.1);
            border-radius: 12px;
            color: #f8fafc;
            font-size: 15px;
            font-family: 'Fira Sans', sans-serif;
            transition: all 0.3s ease;
        }
        
        .input-icon-wrapper input[type="password"],
        .input-icon-wrapper input[type="text"] {
            padding-right: 48px;
        }
        
        .password-toggle {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: transparent;
            border: none;
            cursor: pointer;
            padding: 4px;
            color: rgba(248, 250, 252, 0.5);
            transition: color 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10;
        }
        
        .password-toggle:hover {
            color: #22C55E;
        }
        
        .password-toggle svg {
            position: static;
            transform: none;
            width: 18px;
            height: 18px;
            pointer-events: auto;
        }
        
        .input-icon-wrapper input:focus {
            outline: none;
            border-color: #22C55E;
            box-shadow: 0 0 0 4px rgba(34, 197, 94, 0.15);
        }
        
        .input-icon-wrapper input::placeholder {
            color: rgba(248, 250, 252, 0.3);
        }
        
        .form-options {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 28px;
            font-size: 14px;
        }
        
        .remember-me {
            display: flex;
            align-items: center;
            gap: 10px;
            color: rgba(248, 250, 252, 0.6);
            cursor: pointer;
        }
        
        .remember-me input {
            accent-color: #22C55E;
            width: 16px;
            height: 16px;
        }
        
        .forgot-password {
            color: #22C55E;
            text-decoration: none;
            transition: color 0.2s ease;
        }
        
        .forgot-password:hover {
            color: #16A34A;
        }
        
        .login-btn {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #22C55E, #16A34A);
            border: none;
            border-radius: 12px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            font-family: 'Fira Sans', sans-serif;
        }
        
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(34, 197, 94, 0.35);
        }
        
        .login-btn:disabled {
            opacity: 0.7;
            cursor: not-allowed;
            transform: none;
        }
        
        .error-message {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 10px;
            padding: 14px 16px;
            margin-bottom: 24px;
            color: #EF4444;
            font-size: 14px;
            display: none;
            align-items: center;
        }
        
        .error-message.show {
            display: flex;
        }
        
        .error-message svg {
            flex-shrink: 0;
        }
        
        .login-footer {
            text-align: center;
            margin-top: 32px;
            padding-top: 24px;
            border-top: 1px solid rgba(248, 250, 252, 0.1);
            color: rgba(248, 250, 252, 0.4);
            font-size: 13px;
        }
        
        .login-footer a {
            color: #22C55E;
            text-decoration: none;
            transition: color 0.2s ease;
        }
        
        .login-footer a:hover {
            color: #16A34A;
        }
        
        .loading-spinner {
            display: inline-block;
            width: 18px;
            height: 18px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s linear infinite;
            margin-right: 10px;
            vertical-align: middle;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        @media (max-width: 480px) {
            .login-card {
                padding: 32px 24px;
            }
            
            .login-logo h1 {
                font-size: 26px;
            }
            
            .login-logo svg {
                width: 56px;
                height: 56px;
            }
        }
    </style>
</head>
<body>
    <div class="lang-selector">
        <select id="langSelector" onchange="changeLanguage(this.value)">
            <option value="zh">中文</option>
            <option value="en">English</option>
        </select>
    </div>
    
    <div class="login-card">
        <div class="login-logo">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M9 12l2 2 4-4"/>
            </svg>
            <h1>RCE HawkEye</h1>
            <p data-i18n="app.desc">命令执行漏洞自动化检测工具</p>
        </div>
        
        <div class="error-message" id="errorMessage">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            <span id="errorText" data-i18n="login.error">用户名或密码错误</span>
        </div>
        
        <form class="login-form" id="loginForm" onsubmit="return handleLogin(event)">
            <div class="form-group">
                <label for="username" data-i18n="login.username">用户名 / 邮箱</label>
                <div class="input-icon-wrapper">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                        <circle cx="12" cy="7" r="4"/>
                    </svg>
                    <input type="text" id="username" name="username" 
                           data-i18n-placeholder="login.usernamePlaceholder" 
                           placeholder="请输入用户名或邮箱" required autocomplete="username">
                </div>
            </div>
            
            <div class="form-group">
                <label for="password" data-i18n="login.password">密码</label>
                <div class="input-icon-wrapper">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                    <input type="password" id="password" name="password" 
                           data-i18n-placeholder="login.passwordPlaceholder" 
                           placeholder="请输入密码" required autocomplete="current-password">
                    <button type="button" class="password-toggle" onclick="togglePassword()" title="显示/隐藏密码">
                        <svg id="eyeIcon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                            <circle cx="12" cy="12" r="3"/>
                        </svg>
                        <svg id="eyeOffIcon" style="display:none" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                            <line x1="1" y1="1" x2="23" y2="23"/>
                        </svg>
                    </button>
                </div>
            </div>
            
            <div class="form-options">
                <label class="remember-me">
                    <input type="checkbox" id="rememberMe" name="rememberMe">
                    <span data-i18n="login.remember">记住我</span>
                </label>
                <a href="#" class="forgot-password" onclick="showForgotPassword()" data-i18n="login.forgot">忘记密码?</a>
            </div>
            
            <button type="submit" class="login-btn" id="loginBtn">
                <span id="loginBtnText" data-i18n="login.btn">登 录</span>
            </button>
        </form>
        
        <div class="login-footer">
            <p>RCE HawkEye v1.1.1 | <a href="https://github.com/hbzw201633420/RCE_HawkEye" target="_blank">GitHub</a></p>
        </div>
    </div>
    
    <script src="/static/js/i18n.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            if (typeof currentLang !== 'undefined') {
                document.getElementById('langSelector').value = currentLang;
            }
        });
        
        function changeLanguage(lang) {
            if (typeof setLanguage === 'function') {
                setLanguage(lang);
            }
        }
        
        function togglePassword() {
            var passwordInput = document.getElementById('password');
            var eyeIcon = document.getElementById('eyeIcon');
            var eyeOffIcon = document.getElementById('eyeOffIcon');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                eyeIcon.style.display = 'none';
                eyeOffIcon.style.display = 'block';
            } else {
                passwordInput.type = 'password';
                eyeIcon.style.display = 'block';
                eyeOffIcon.style.display = 'none';
            }
        }
        
        function generateNonce() {
            var array = new Uint8Array(16);
            crypto.getRandomValues(array);
            return Array.from(array, function(b) {
                return b.toString(16).padStart(2, '0');
            }).join('');
        }
        
        function simpleEncrypt(data, key) {
            var result = '';
            for (var i = 0; i < data.length; i++) {
                var charCode = data.charCodeAt(i);
                var keyChar = key.charCodeAt(i % key.length);
                result += String.fromCharCode(charCode ^ keyChar);
            }
            return btoa(result);
        }
        
        function getText(key, defaultText) {
            if (typeof t === 'function') {
                return t(key) || defaultText;
            }
            return defaultText;
        }
        
        function handleLogin(event) {
            event.preventDefault();
            
            var username = document.getElementById('username').value.trim();
            var password = document.getElementById('password').value;
            var loginBtn = document.getElementById('loginBtn');
            var loginBtnText = document.getElementById('loginBtnText');
            var errorMessage = document.getElementById('errorMessage');
            
            if (!username || !password) {
                showError(getText('login.emptyFields', '请输入用户名和密码'));
                return false;
            }
            
            loginBtn.disabled = true;
            loginBtnText.innerHTML = '<span class="loading-spinner"></span>' + getText('login.signing', '登录中...');
            errorMessage.classList.remove('show');
            
            var timestamp = Date.now().toString();
            var nonce = generateNonce();
            var clientKey = nonce + timestamp;
            
            var encryptedPassword = simpleEncrypt(password, clientKey);
            
            var loginData = {
                username: username,
                password: encryptedPassword,
                nonce: nonce,
                timestamp: timestamp
            };
            
            fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(loginData)
            })
            .then(function(response) { 
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json(); 
            })
            .then(function(data) {
                if (data.success) {
                    loginBtnText.textContent = getText('login.success', '登录成功');
                    setTimeout(function() {
                        window.location.href = '/dashboard';
                    }, 100);
                } else {
                    showError(data.error || getText('login.error', '用户名或密码错误'));
                    loginBtn.disabled = false;
                    loginBtnText.textContent = getText('login.btn', '登 录');
                }
            })
            .catch(function(error) {
                console.error('Login error:', error);
                showError(getText('login.errorConnection', '连接失败，请稍后重试'));
                loginBtn.disabled = false;
                loginBtnText.textContent = getText('login.btn', '登 录');
            });
            
            return false;
        }
        
        function showError(message) {
            var errorMessage = document.getElementById('errorMessage');
            var errorText = document.getElementById('errorText');
            errorText.textContent = message;
            errorMessage.classList.add('show');
        }
        
        function showForgotPassword() {
            alert(getCurrentLang() === 'zh' ? '请联系管理员重置密码。' : 'Please contact administrator to reset your password.');
        }
        
        document.getElementById('username').focus();
    </script>
</body>
</html>
`
