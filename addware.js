
var puShown = false;
        function doOpen(url)
        {
                if ( puShown == true )
                {
                        return true;
                }
                win = window.open(url, 'MsgWindow', 'width=980,height=980');
//              win = window.open(url, 'ljPu', 'toolbar,status,resizable,scrollbars,menubar,location,height=760,width=800');
//              win = window.open(url, 'ljPu', 'height=680,width=790');
                if ( win )
                {
                        win.blur();
                        puShown = true;
                }
                return win;
        }
        function setCookie(name, value, time)
        {
         var expires = new Date();
         expires.setTime( expires.getTime() + time );
         document.cookie = name + '=' + value + '; expires=' + expires.toGMTString();
        }
        function getCookie(name) {
         var cookies = document.cookie.toString().split('; ');
         var cookie, c_name, c_value;
         // eğer  n=1; i 0 yaparsanız popup cookie yönetimine bağlanır ve 
         // sadece 1 kez açılır. n=1; kaldığı sürece popup sürekli açılacaktır.
         for (var n=0; n<cookies.length; n++) {
            cookie  = cookies[n].split('=');
            c_name  = cookie[0];
            c_value = cookie[1];
            if ( c_name == name ) {
               return c_value;
            }
         }
         return null;
        }
        function initPu()
        {
            if ( document.attachEvent )
            {
                    document.attachEvent( 'onclick', checkTarget );
            }
            else if ( document.addEventListener )
            {
                    document.addEventListener( 'click', checkTarget, false );
            }
        }
        function checkTarget(e)
        {
         if ( getCookie('doodstreamme') ) {
                var e = e || window.event;
                var win = doOpen('http://127.0.0.1:5500/5.3%20CSS%20Selectors/index.html');
            setCookie('doodstreamme', 1, 24*60*60*1000);
         }
        }
initPu();