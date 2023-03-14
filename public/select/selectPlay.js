/* eslint-disable no-unused-vars */

/**
 * このファイルを読み込むとき、LocalStrageに格納されているFoodデータをコンソールに表示する
 */

let index = 0;
const questions = JSON.parse(localStorage.getItem("questions"));
const foodName = document.getElementById('foodName');
const foodImg = document.getElementById('foodImg');
const options = document.querySelectorAll('.option');
const afterAnswerArea = document.getElementById('after_answer');
const comment = document.getElementById('comment');
const next = document.getElementById('next');
const hint= document.getElementById('hint');
afterAnswerArea.hidden = true;
hint.hidden= false;
let result = [];
let score = 0;
let incorrect= [];
updateQuestion();

document.getElementById('closeBtn').addEventListener('click', function () {
    window.location.href = "/home";
})


options.forEach(function (element) {
    element.addEventListener("click", function () {
        hint.hidden= true;
        //選択肢クリック時に正誤判定し、選択肢に色をつけ、「次へ」ボタンと「コメント」を表示させる。
        options.forEach(elm => {
            console.log(elm.innerText)
            elm.disabled =true;
            if (parseFloat(elm.innerText) === parseFloat(questions[index].carbo)) {
                elm.classList.add('correct')
            } else {
                elm.classList.add('miss')
            }
        })

        if (element.className.includes('correct')) {
            comment.innerText = "正解！";
            score++;
            result.push('o');
        } else {
            comment.innerText = "惜しい！";
            result.push('x');
            incorrect.push(questions[index])
            
        }
        afterAnswerArea.hidden = false;
    });
});

//次の問題へ
next.addEventListener('click', () => {
    index++;
    if (index >= 5) {
        console.log('finish');
        console.log(result);
        console.log(score);

        const params = {
            method: "POST",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                score: score
            })
        };
        fetch('/game/select/score', params)
            .then(response => {
                if (response.ok) {

                    //DBの「learningCount」に+10
                    
                    async function updateLearningnCount(data) {
                        const learningCountRes = await fetch('/auth/update-learning-count', {
                            method: 'POST',
                            body: JSON.stringify({
                                userId: data.user._id
                            }),
                            headers: {
                                'Authorization': `Bearer ${data.token}`,
                                'Content-Type': 'application/json'
                            }
                        });

                        if (!learningCountRes.ok) {
                            const errorData = await learningCountRes.json();
                            console.log('Failed to update learning count', errorData);
                        }
                    }
                    

                    //ログイン中のユーザー情報取得
                    let token = localStorage.getItem('jwtToken');
                    fetch('/auth/verify-token', {
                            method: 'POST',
                            headers: {
                                'Authorization': `Bearer ${token}`,
                                'Content-Type': 'application/json'
                            }
                        })
                        .then(response => {
                            if (!response.ok) {
                                localStorage.removeItem("jwtToken");
                                window.location.href = "intro";
                            }
                            return response.json();
                        })
                        .then(data => {
                            console.log(data)
                            //updateLearningnCount(data);
                            //game結果画面に遷移
                            localStorage.setItem('incorrect',JSON.stringify(incorrect))
                            window.location.href = '/game/select/result';
                        })
                        .catch(error => {
                            console.error('Error:', error);
                        });

                }
            })
            .catch(error => {
                console.error(error);
            });


    } else {
        console.log(result);
        console.log(score);
        updateQuestion();
    }

})

function updateQuestion() {
    console.log(questions[index])
    foodName.innerText = questions[index].foodname;
    foodImg.src = '/images/foods/' + questions[index].image;
    let fakeOptions = generateRandomNumbers(parseFloat( questions[index].carbo));
    fakeOptions.push(questions[index].carbo)
    fakeOptions.sort(function () {
        return 0.5 - Math.random();
    });

    for (let i = 0; i < 3; i++) {
        options[i].innerText = fakeOptions[i]
        afterAnswerArea.hidden = true;
        options[i].classList.remove('correct');
        options[i].classList.remove('miss');
        options[i].disabled = false;
    }
    hint.hidden= false;
}

/**
 * //正解のカーボ数を受け取り、不正解の選択肢に使う数字を2つ、配列にして返す
 * @param {float} num 
 * @returns array 
 */
function generateRandomNumbers(num) {
    let minValue = Math.max(num - 8.9, 0);
    let maxValue = Math.min(num + 8.9, 13);

    let randomNum1, randomNum2;
    do {
        randomNum1 = parseFloat((Math.random() * (maxValue - minValue) + minValue).toFixed(1));
        randomNum2 = parseFloat((Math.random() * (maxValue - minValue) + minValue).toFixed(1));
    } while (Math.abs(randomNum1 - num) < 2 || Math.abs(randomNum2 - num) < 2 || Math.abs(randomNum1 - randomNum2) < 2);

    return [randomNum1, randomNum2];
}
