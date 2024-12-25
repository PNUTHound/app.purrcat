const body = document.body;
const image = body.querySelector('#coin');
const h1 = body.querySelector('h1');

let coins = localStorage.getItem('coins');
let total = localStorage.getItem('total');
let power = localStorage.getItem('power');
let count = localStorage.getItem('count');

if(coins == null){
    localStorage.setItem('coins' , '0');
    h1.textContent = '0';
}else{
    h1.textContent = Number(coins).toLocaleString();
}

if(total == null){
    localStorage.setItem('total' , '24');
    body.querySelector('#total').textContent = '/24';
}else {
    body.querySelector('#total').textContent = `/${total}`;
}

if(power == null){
    localStorage.setItem('power' , '24');
    body.querySelector('#power').textContent = '24';
}else{
    body.querySelector('#power').textContent = power;
}

if(count == null){
    localStorage.setItem('count' , '1');
}

image.addEventListener('click' , (e)=> {
    let x = e.offsetX;
    let y = e.offsetY;

    navigator.vibrate(5);

    coins = localStorage.getItem('coins');
    power = localStorage.getItem('power');
    
    if(Number(power) > 0){
        localStorage.setItem('coins' , `${Number(coins) + 1}`);
        h1.textContent = `${(Number(coins) + 1).toLocaleString()}`;
    
        localStorage.setItem('power' , `${Number(power) - 1}`);
        body.querySelector('#power').textContent = `${Number(power) - 1}`;
    } 

    if(x < 150 && y < 150){
        image.style.transform = 'translate(-0.25rem, -0.25rem) skewY(-10deg) skewX(5deg)';
    }
    else if (x < 150 && y > 150){
        image.style.transform = 'translate(-0.25rem, 0.25rem) skewY(-10deg) skewX(5deg)';
    }
    else if (x > 150 && y > 150){
        image.style.transform = 'translate(0.25rem, 0.25rem) skewY(10deg) skewX(-5deg)';
    }
    else if (x > 150 && y < 150){
        image.style.transform = 'translate(0.25rem, -0.25rem) skewY(10deg) skewX(-5deg)';
    }

    setTimeout(()=>{
        image.style.transform = 'translate(0px, 0px)';
    }, 100);

    body.querySelector('.progress').style.width = `${(100 * power) / total}%`;
});

setInterval(()=> {
    power = localStorage.getItem('power');  
    total = localStorage.getItem('total');
    if(Number(total) > Number(power)){
        localStorage.setItem('power' , `${Number(power) + 1}`);
        body.querySelector('#power').textContent = `${Number(power) + 1}`;
        body.querySelector('.progress').style.width = `${(100 * power) / total}%`;
    }
}, 60 * 60 * 1000);  // 1 hour interval
