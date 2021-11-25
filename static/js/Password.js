const password = document.querySelector("#password");
const togglePassword = document.querySelector("#togglePassword"); 
const rmCheck = document.getElementById("rememberMe"),
    emailInput = document.getElementById("email");

togglePassword.addEventListener('click', function (e) {
    //toggle the type attribute
    const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
    password.setAttribute('type', type);
    //toggle the eye/eye slash icon
    this.classList.toggle('fa-eye-slash');
});



if (localStorage.checkbox && localStorage.checkbox != ""){
    rmCheck.setAttribute("checked", "checked");
    emailInput.value = localStorage.username;
}else{
    rmCheck.removeAttribute("checked");
    emailInput.value = "";
}
function lsRememberMe(){
    if(rmCheck.checked && emailInput.value != ""){
        localStorage.username = emailInput.value;
        localStorage.checkbox = rmCheck.value;
    }else{
        localStorage.username = "";
        localStorage.checkbox = "";
    }
}

