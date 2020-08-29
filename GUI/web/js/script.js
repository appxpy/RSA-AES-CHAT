function renderUser(list) { 
    console.log(list[0]);
    
    let filepath = list[0];
    let user = list[1];
    let status = list[2];
    var lowerStatus = status.toLocaleLowerCase();
    $userlist = $('.list');
    let template = Handlebars.compile($("#user-template").html());
    let imgpath = filepath + '_' + lowerStatus + '.png';
    let context = {
        imgpath: imgpath,
        username: user,
        status: lowerStatus,
        status2: status
    };


    $userlist.append(template(context));
}

function loadData() {
    let urlParams = new URLSearchParams(window.location.search);
    let obj = decodeURIComponent(urlParams.get('data'));
    obj = JSON.parse(obj);
    console.log(obj.status);

    Object.entries(obj.users).forEach(function([user, status]) {
        eel.generatePic(user, status)(renderUser);
    });

}

document.addEventListener("DOMContentLoaded", loadData);