package TakeMFA::Console;
use strict;
use warnings;
use utf8;
use TakeMFA::View ();
use TakeMFA::QR ();
our $CPANEL=0;
sub e {return TakeMFA::View::escape($_[0]);}
sub icon {
    my ($name)=@_;
    my %paths=(shield=>'<path d="M12 3 3.5 6v5c0 5 3.5 8 8.5 10 5-2 8.5-5 8.5-10V6L12 3Z"/><path d="m8 12 3 3 5-6"/>',lock=>'<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',phone=>'<rect x="6" y="2" width="12" height="20" rx="3"/><path d="M10 18h4M10 5h4"/>',key=>'<circle cx="8" cy="9" r="5"/><path d="m12 13 8 8m-4-4 3-3m-6 0 3-3"/>',server=>'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6h.01M7 17h.01M12 6h5m-5 11h5"/>');
    return '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'.($paths{$name}//$paths{shield}).'</svg>';
}
sub control {
    my ($url,$nonce,$action,$title,$text,$button,$danger,$target)=@_;
    my $body='<details'.($danger?' class="danger"':'').'><summary>'.e($title).'</summary><div class="detail-body"><p>'.e($text).'</p>';
    $body.='<form method="post" action="'.e($url).'" autocomplete="off"><input type="hidden" name="action" value="'.e($action).'"><input type="hidden" name="nonce" value="'.e($nonce).'">';
    $body.='<input type="hidden" name="target" value="'.e($target).'">' if defined($target);
    unless($action eq 'cancel_rotation'){
        $body.='<label for="code-'.e($action).'">رمز جديد من التطبيق أو رمز استرداد غير مستخدم</label><input type="text" name="code" id="code-'.e($action).'" dir="ltr" autocomplete="one-time-code" maxlength="32" placeholder="000 000" required><p class="inline-note">إذا تحققت للتو، انتظر الرمز التالي. كل رمز يُقبل مرة واحدة.</p>';
    }
    if($danger){$body.='<label class="check"><input type="checkbox" name="ack" value="1" required>أفهم أثر هذا الإجراء وأؤكد تنفيذه.</label>';}
    return $body.'<button type="submit">'.e($button).'</button></form></div></details>';
}
sub render {
    my ($u,$prefix,$d,$setup,$result,$message,$error)=@_;my $url=$prefix.($CPANEL?'/frontend/jupiter/take_mfa/index.live.pl':'/cgi/take-mfa.cgi');
    my $active=$d->{enrolled} && !$d->{paused} && $d->{global_enabled};
    my $state=$active?'الحماية مفعّلة':$d->{enrolled}?'الحماية متوقفة':'جاهز للإعداد';
    my $body='<div class="identity"><div class="identity-main"><span class="avatar">'.e(uc(substr($u,0,1))).'</span><div><strong dir="ltr">'.e($u).'</strong><small>'.($u eq 'root'?'مدير الخادم · صلاحية التحكم العامة':'إعدادات حسابك · WHM وcPanel').'</small></div></div><span class="pill'.($active?'':' off').'">'.$state.'</span></div>';
    $body.='<nav class="tabs" aria-label="أقسام الحماية"><a class="active" href="#account">حماية حسابي</a><a href="#recovery">الأمان والاسترداد</a>'.($u eq 'root'?'<a href="#server">إدارة الخادم</a>':'').'</nav>';
    $body.='<div class="notice success" role="status">'.e($message).'</div>' if $message;
    $body.='<div class="error" role="alert">'.e($error).'</div>' if $error;
    $body.='<div class="warning">الإضافة متوقفة على مستوى الخادم. عوامل الحسابات محفوظة، لكن تحدي الدخول المخصص لا يُطلب حاليًا. يستطيع root إعادة تشغيله من قسم إدارة الخادم.</div>' unless $d->{global_enabled};
    if($result && $result->{recovery_codes}){
        $body.='<section class="card" id="new-recovery"><div class="card-body"><span class="section-label">RECOVERY KIT</span><h2>احفظ رموز الاسترداد الآن</h2><p class="muted">تظهر هذه الرموز مرة واحدة فقط. كل رمز يعمل مرة واحدة بدل تطبيقك. الرموز القديمة لم تعد صالحة.</p><div class="recovery-grid">';
        $body.=join('',map {'<code>'.e(join('-',unpack('(A6)*',$_))).'</code>'} @{$result->{recovery_codes}});
        $body.='</div><div class="warning">احفظها في مدير كلمات مرور أو في مكان آمن خارج هذا الخادم. لا ترسلها في محادثة أو لقطة شاشة.</div></div></section><div class="layout-full"></div>';
    }
    $body.='<div class="grid"><section id="account" class="card">';
    if($setup){
        my $rotation=$setup->{rotation};
        $body.='<div class="card-head"><h2>'.icon('phone').($rotation?' ربط تطبيق جديد بأمان':' إعداد تطبيق Authenticator').'</h2><span class="status-count">خطوتان فقط</span></div><div class="card-body">';
        $body.='<div class="notice">يبقى المفتاح السابق فعالًا حتى تؤكد الرمز من التطبيق الجديد. بعد التأكيد تُلغى رموز الاسترداد والجلسات الموثقة السابقة.</div>' if $rotation;
        my $svg=TakeMFA::QR::svg($u,$setup->{secret});
        $body.='<div class="setup-grid"><div>'.($svg?'<div class="qr-wrap" data-take-mfa="qr">'.$svg.'</div><div class="qr-caption">يُولَّد محليًا · لا تشارك صورة الرمز</div>':'<div class="warning">تعذر عرض QR. استخدم مفتاح الإعداد اليدوي أدناه.</div>').'</div><div><div class="step"><span class="step-num">1</span><div><b>افتح تطبيق المصادقة</b><p>Google Authenticator أو Microsoft Authenticator على هاتفك.</p></div></div><div class="step"><span class="step-num">2</span><div><b>امسح QR بكاميرا التطبيق</b><p>اختر إضافة حساب ثم «مسح رمز QR». سيظهر باسم <span dir="ltr">TakeYourHost WHM:'.e($u).'</span>.</p></div></div><div class="step"><span class="step-num">3</span><div><b>أكّد الرمز لبدء الحماية</b><p>أدخل رمز التطبيق المكون من 6 أرقام في الحقل التالي.</p></div></div></div></div>';
        $body.='<details class="manual"><summary>لا تستطيع مسح QR؟ استخدم مفتاح الإعداد اليدوي</summary><div class="detail-body"><p>نوع الحساب: زمني / Time-based، 6 أرقام، كل 30 ثانية.</p><code data-take-mfa="setup-key">'.e($setup->{secret}).'</code><p class="inline-note">هذا مفتاح سري؛ لا ترسله أو تصوره.</p></div></details>';
        $body.='<div class="setup-confirm"><h3><span class="step-num">✓</span> تأكيد '.($rotation?'التطبيق الجديد':'تفعيل الحماية').'</h3><p class="muted">تنتهي محاولة الإعداد بعد 10 دقائق. لا يتم التفعيل حتى تقبل الإضافة رمزًا صحيحًا.</p>'.TakeMFA::View::form($url,$setup->{nonce},'رمز التحقق من التطبيق',$rotation?'confirm_rotation':'confirm','تأكيد '.($rotation?'المفتاح الجديد':'وتفعيل الحماية')).'</div>';
        $body.=control($url,$d->{nonce},'cancel_rotation','إلغاء استبدال التطبيق','سيظل التطبيق السابق كما هو.','إلغاء الاستبدال',0) if $rotation;
        $body.='</div>';
    }
    else{
        $body.='<div class="hero-status'.($active?'':' off').'"><span class="shield">'.icon('shield').'</span><div><h2 data-take-mfa="enabled">'.($active?'حسابك محمي بخطوة إضافية':'العامل مسجّل والحماية متوقفة').'</h2><p>التطبيق مرتبط بحسابك. لا يُعرض المفتاح الحالي مرة أخرى.</p></div></div><div class="metrics"><div class="metric"><small>رموز الاسترداد المتبقية</small><b>'.e($d->{recovery_count}).'<span class="muted"> / 10</span></b></div><div class="metric"><small>طريقة التحقق</small><b class="text">تطبيق Authenticator</b></div></div><div class="card-body"><h3>التحكم في حماية حسابي</h3><p class="muted">كل تغيير حساس يتطلب رمزًا حديثًا، حتى داخل جلسة سبق التحقق منها.</p>';
        $body.= $d->{paused}?control($url,$d->{nonce},'resume','تشغيل حماية حسابي','إعادة استخدام التطبيق المرتبط حاليًا. لا يلزم مسح QR جديد.','تأكيد تشغيل الحماية',0):control($url,$d->{nonce},'pause','إيقاف حماية حسابي','لن يُطلب العامل المخصص لحسابك في WHM وcPanel بعد الإيقاف. سيظل التطبيق ومفاتيح الاسترداد محفوظة لإعادة التشغيل. لا يتأثر أي حساب آخر.','تأكيد إيقاف الحماية',1);
        $body.=control($url,$d->{nonce},'rotate','استبدال الهاتف أو مفتاح الإعداد','بعد التحقق ستظهر شاشة QR جديد. يبقى التطبيق القديم فعالًا حتى تأكيد رمز من التطبيق الجديد.','متابعة لربط تطبيق جديد',1);
        $body.='</div>';
    }
    $body.='</section><aside class="stack"><section class="card" id="recovery"><div class="card-head"><h2>'.icon('lock').' الأمان والاسترداد</h2></div><div class="card-body"><span class="section-label">SECURITY CHECKLIST</span><div class="helper-row">'.icon('key').'<div><b>احتفظ بطريق استرداد</b><p>رموز الاسترداد بديل للهاتف عند فقدانه. احتفظ بها خارج الخادم.</p></div></div><div class="helper-row">'.icon('shield').'<div><b>حساب مستقل لكل مسؤول</b><p>لا تشارك التطبيق أو المفتاح. يربط كل ريسيلر تطبيقه بحسابه.</p></div></div><div class="helper-row">'.icon('phone').'<div><b>لا تشارك QR أو مفتاح الإعداد</b><p>من يملك المفتاح يستطيع توليد الرموز نفسها. استبدله إذا انكشف.</p></div></div>';
    $body.=control($url,$d->{nonce},'recovery','إنشاء رموز استرداد جديدة','ستُلغى جميع رموز الاسترداد السابقة فور التأكيد، وتظهر 10 رموز جديدة مرة واحدة فقط.','إنشاء رموز جديدة',1) if $d->{enrolled};
    $body.='</div></section><section class="card"><div class="card-body"><h3>ما الذي تحميه الإضافة؟</h3><p class="muted">دخول WHM وcPanel للمستخدم المسجّل. لا تغيّر إعدادات المواقع أو البريد، ولا تحمي SSH أو رموز API بدلًا من تأمينها بشكل مستقل.</p><a class="button secondary" href="'.e($prefix).'/">العودة إلى لوحة الاستضافة ←</a></div></section></aside></div>';
    if($u ne 'root' && $d->{enrolled}){
        my $cpactive=$active && !$d->{cpanel_paused};
        $body.='<section id="cpanel" class="card layout-full"><div class="card-head"><h2>'.icon('shield').' حماية دخول cPanel</h2><span class="pill'.($cpactive?'':' off').'">'.($cpactive?'مفعّلة':'متوقفة').'</span></div><div class="card-body"><p class="muted">نفس التطبيق والمفتاح يحميان WHM وcPanel للمستخدم نفسه، مع تحقق مستقل لكل جلسة. هذا الخيار يغيّر حماية cPanel فقط، ولا يغيّر إعداد WHM. الإيقاف العام للعامل أو الإضافة يتقدم على هذا الخيار.</p>';
        $body.=$d->{cpanel_paused}?control($url,$d->{nonce},'resume_cpanel','تشغيل حماية cPanel فقط','استخدم التطبيق المرتبط حاليًا لإعادة تفعيل تحدي الدخول إلى cPanel لهذا الحساب.','تأكيد تشغيل حماية cPanel',0):control($url,$d->{nonce},'pause_cpanel','إيقاف حماية cPanel فقط','لن يُطلب العامل المخصص عند دخول cPanel لهذا الحساب. يبقى إعداد WHM كما هو.','تأكيد إيقاف حماية cPanel',1);
        $body.='</div></section>';
    }
    if(@{$d->{clients}||[]}){
        $body.='<section id="clients" class="card layout-full"><div class="card-head"><h2>'.icon('server').' حماية حسابات cPanel التابعة لك</h2><span class="status-count">'.scalar(@{$d->{clients}}).' حساب</span></div><div class="card-body"><p class="muted">يُعد كل عميل تطبيقه بنفسه من قسم Security في cPanel. يمكنك بعد ذلك إيقاف أو تشغيل تحدي cPanel للحساب المملوك لك، بتأكيد رمز تطبيقك أنت. لا تظهر مفاتيح العملاء هنا، ولا يتغير تطبيقهم. تشغيل cPanel لا يتجاوز إيقاف العميل العام للعامل أو الإيقاف العام للإضافة.</p>';
        $body.='<div class="notice">فعّل عامل حسابك أولًا لإتاحة إدارة حماية العملاء.</div>' unless $d->{enrolled};
        for my $row(@{$d->{clients}}){
            $body.='<details><summary><span dir="ltr">'.e($row->{name}).'</span> — '.(!$row->{enrolled}?'لم يُعدّ التطبيق بعد':($row->{paused} || $row->{cpanel_paused})?'حماية cPanel متوقفة':'عامل الحساب مفعّل').'</summary><div class="detail-body">';
            if($row->{enrolled} && $d->{enrolled}){
                my $resume=$row->{cpanel_paused};
                $body.=control($url,$d->{nonce},$resume?'client_resume':'client_pause',$resume?'تشغيل حماية cPanel':'إيقاف حماية cPanel','هذا الإجراء يخص حساب '. $row->{name}.' فقط. أكّد برمز حسابك أنت، وليس رمز العميل.',$resume?'تأكيد التشغيل للحساب':'تأكيد الإيقاف للحساب',1,$row->{name});
            }else{$body.='<p>على صاحب الحساب فتح TakeYourHost Authenticator داخل cPanel ومسح QR ثم تأكيد الرمز أولًا. لا تُنشأ مفاتيح للعملاء نيابة عنهم.</p>';}
            $body.='</div></details>';
        }
        $body.='</div></section>';
    }
    if($u eq 'root'){
        $body.='<section id="server" class="card layout-full"><div class="card-head"><h2>'.icon('server').' إدارة الإضافة على الخادم</h2><span class="pill'.($d->{global_enabled}?'':' off').'">'.($d->{global_enabled}?'قيد التشغيل':'متوقفة').'</span></div><div class="card-body"><p class="muted">هذا القسم متاح لـroot فقط. التشغيل والإيقاف هنا يخصان الإضافة المخصصة، ولا يغيران مصادقة WHM الأصلية. تبقى عوامل الحسابات محفوظة.</p>';
        if($d->{enrolled}){
            $body.=$d->{global_enabled}?control($url,$d->{nonce},'global_off','إيقاف الإضافة لجميع الحسابات','تحذير: لن تطلب هذه الإضافة العامل الثاني لأي حساب على الخادم حتى تعيد تشغيلها. لا تُحذف العوامل أو تُوقف أي خدمة.','تأكيد الإيقاف على الخادم',1):control($url,$d->{nonce},'global_on','تشغيل الإضافة لجميع الحسابات','تعود مطالبة الحسابات المسجّلة بالتحقق، باستثناء الحسابات التي أوقفت عاملها بنفسها.','تأكيد تشغيل الإضافة',0);
        }else{$body.='<div class="notice">اربط تطبيق Authenticator بحساب root أولًا لإتاحة التحكم العام المحمي بالرمز.</div>';}
        $body.='</div><table><thead><tr><th>الحسابات المسجلة في الإضافة</th><th>حالة عامل الحساب</th></tr></thead><tbody>';
        for my $row(@{$d->{accounts}||[]}){$body.='<tr><td dir="ltr">'.e($row->{name}).'</td><td><span class="pill'.($row->{paused}?' off':'').'">'.($row->{paused}?'متوقف للحساب':'مفعّل للحساب').'</span></td></tr>';}
        $body.='<tr><td colspan="2" class="muted">لا توجد حسابات مسجلة حتى الآن.</td></tr>' unless @{$d->{accounts}||[]};
        $body.='</tbody></table></section>';
    }
    return $body.'<div class="security-note">'.icon('shield').'<span>لا يغني العامل الثاني عن حماية كلمة المرور ورموز API وإصلاح مصدر الاختراق. احتفظ بوصول SSH آمن للطوارئ.</span></div>';
}
1;
