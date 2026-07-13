/**
 * iOS 证书在线检测 — client-side cert checker.
 * Deobfuscated (1:1) from the original obfuscated version.
 *
 * Behavior preserved exactly. The only external network call is
 * POST https://ckapi.ipasign.cc/checkcert which validates the
 * uploaded p12 / mobileprovision / ipa cert(s) and returns JSON
 * describing the certificate state. All DOM interactions match the
 * element IDs defined in index.html.
 */

/* upload state — set true while a request is in flight */
var uploading = false;
var file_item = null;
var this_input = null;

/* -------------------------------------------------------------------------
 * i18n string table
 * ---------------------------------------------------------------------- */
var i18n = {
    zh: {
        wrongFormat:      '文件格式不正确，仅支持 p12、mobileprovision、ipa 格式文件',
        passwordTitle:    '密码',
        statusRevoked:    '掉签',
        statusExpired:    '过期',
        statusGood:       '正常',
        statusUnknown:    '未知',
        provisionMatched: '与证书匹配',
        country:          '国家',
    },
    en: {
        wrongFormat:      'Invalid file type. Only p12, mobileprovision, and ipa files are supported.',
        passwordTitle:    'Password',
        statusRevoked:    'Revoked',
        statusExpired:    'Expired',
        statusGood:       'Valid',
        statusUnknown:    'Unknown',
        provisionMatched: 'Matches Certificate',
        country:          'Country',
    }
};

function t(key) {
    var lang = (typeof currentLang !== 'undefined') ? currentLang : 'zh';
    return i18n[lang][key] || i18n['zh'][key];
}

/* -------------------------------------------------------------------------
 * Drag & drop wiring
 * ---------------------------------------------------------------------- */
document.ondragover = function (e) { e.preventDefault(); };
document.ondrop     = function (e) { e.preventDefault(); };

uploadIpa.ondragover = function (e) { e.preventDefault(); };
uploadIpa.ondrop     = function (e) {
    e.preventDefault();
    handleFileUpload(e.dataTransfer.files);
};

$('#uploadIpa').click(function () {
    $('#uploadfile').trigger('click');
});

/* -------------------------------------------------------------------------
 * File intake
 * ---------------------------------------------------------------------- */
function handleFileUpload(files) {
    file_item = files[0];
    var allowed = ['ipa', 'p12', 'mobileprovision'];
    var ext     = file_item.name.split('.').pop().toLocaleLowerCase();

    if (allowed.indexOf(ext) === -1) {
        alert(t('wrongFormat'));
        return;
    }

    var dot  = file_item.name.lastIndexOf('.');
    var real = file_item.name.substring(dot + 1, file_item.name.length);

    if (real == 'p12' || real == 'P12') {
        layer.prompt({ title: t('passwordTitle'), formType: 1 }, function (password, index) {
            uploads(file_item, password, '');
            layer.close(index);
        });
    } else if (real == 'mobileprovision') {
        uploads('', '', file_item);
    } else if (real == 'ipa') {
        new AppInfoParser(file_item).parse().then(function (info) {
            console.log(info);
            $('#appName').removeClass('hide');
            $('#bundleId').removeClass('hide');
            $('.appNameSpan').html(info.CFBundleDisplayName ? info.CFBundleDisplayName : info.CFBundleName);
            $('.bundleIdSpan').html(info.CFBundleIdentifier);
            $('#certFlag').attr('src', info.icon);
        });
        read(file_item);
    }
}

/* -------------------------------------------------------------------------
 * Read an .ipa — extract embedded.mobileprovision & Info.plist
 * ---------------------------------------------------------------------- */
async function read(file) {
    var provision = await getProvisionFile(file);
    var plist      = await getPlistFile(file);
    uploads('', '', provision, plist);
}

/* -------------------------------------------------------------------------
 * Upload + render the API response
 * ---------------------------------------------------------------------- */
function uploads(p12, password, mp, plist) {
    var formData = new FormData();
    formData.append('p12',      p12 ? p12 : '');
    formData.append('password', password ? password : '');
    formData.append('mp',       mp ? mp : '');

    this_input = $(this);
    $('#shortUrl').css('display', 'none');
    $('#search').removeClass('hide');

    $.ajax({
        url:          'https://ckapi.ipasign.cc/checkcert',
        type:         'POST',
        cache:        false,
        data:         formData,
        processData:  false,
        contentType:  false,
        dataType:     'json',
        beforeSend:   function () { uploading = true; },
        success:      function (res) {
            if (res.code == 0) {
                $('#search').attr('class', 'hide');
                $('#certResult').removeClass('hide');
                $('#fileCertResult').removeClass('hide');

                // Save raw state so the language toggle can re-render these later
                lastCertState   = res.state || 'unknown';
                lastCertType    = res.certType || null;
                lastAttribution = res.attribution || null;

                if (res.state == 'revoked') {
                    $('#revokedDate').removeClass('hide');
                    $('#certStatus').prepend('<span class="text-danger">' + t('statusRevoked') + '</span>');
                    $('#certRevokedDate').html(res.revokedDate);
                    $('#certStatusExplain').attr('data-content', res.revokedReason);
                } else if (res.state == 'expired') {
                    $('#revokedDate').removeClass('hide');
                    $('#certStatus').prepend('<span class="text-danger">' + t('statusExpired') + '</span>');
                    $('#certRevokedDate').html(res.revokedDate);
                    $('#certStatusExplain').attr('data-content', res.revokedReason);
                } else if (res.state == 'good') {
                    $('#certStatusExplain').attr('class', 'hide');
                    $('#certStatus').prepend('<span class="text-success">' + t('statusGood') + '</span>');
                } else {
                    $('#certStatusExplain').attr('class', 'hide');
                    $('#certStatus').prepend('<span class="text-danger">' + t('statusUnknown') + '</span>');
                }

                $('#certName').html(res.certName);
                $('#certExpireDate').html(res.notAfter);
                if (res.certType) {
                    $('#certType').html(res.certType + ' (' + t('country') + ': ' + res.attribution + ')');
                } else if (res.attribution) {
                    $('#certType').html(res.attribution);
                }

                if (res.sha1) {
                    $('#sha1Row').removeClass('hide');
                    $('#certSha1').html(res.sha1);
                }
                if (res.expirationDate) {
                    lastProvisionMatched = true;
                    $('.provision-detail').removeClass('hide');
                    $('#provisionExpireDate').html(res.expirationDate);
                    $('#identifier').html(res.appid);
                    $('#provisionStatus').prepend('<span class="text-success">' + t('provisionMatched') + '</span>');
                }
                if (res.cFBundleName) {
                    lastProvisionMatched = true;
                    $('#provisionStatus').prepend('<span class="text-success">' + t('provisionMatched') + '</span>');
                    $('.bundleIdSpan').html(res.cFBundleIdentifier);
                    $('#certRevokedDate').html(res.revokedDate);
                    $('.appNameSpan').html(res.cFBundleName);
                    $('#bundleId').removeClass('hide');
                    $('#provisionExpireDate').html(res.expirationDate);
                    $('#identifier').html(res.appid);
                    $('#appName').removeClass('hide');
                    $('.provision-detail').removeClass('hide');
                }

                $('#recheckBtn').removeClass('hide');
            } else {
                $('#errorMsg').removeClass('hide');
                $('#errorMsg').prepend('<span style="color: #FD5A5A; font-size: 18px;">' + res.msg + '</span>');
                $('#certResult').removeClass('hide');
                $('#search').attr('class', 'hide');
                $('#recheckBtn').removeClass('hide');
                $('#certDetail').attr('class', 'hide');
            }

            uploading = false;
        }
    });
}

/* -------------------------------------------------------------------------
 * Reload the page (re-check button)
 * ---------------------------------------------------------------------- */
function toggleRes() {
    location.reload();
}

/* -------------------------------------------------------------------------
 * Extract embedded.mobileprovision from an .ipa using UnZipArchive
 * ---------------------------------------------------------------------- */
function getProvisionFile(file) {
    return new Promise(function (resolve) {
        window.un = new UnZipArchive(file);
        un.getData(function () {
            var entries = un.getEntries();
            for (var i = 0; i < entries.length; i++) {
                if (entries[i].indexOf('app/embedded.mobileprovision') != -1) {
                    un.getData(entries[i], function (data) {
                        var provisionFile = new window.File([data], 'embedded.mobileprovision');
                        resolve(provisionFile);
                    });
                }
            }
        });
    });
}

/* -------------------------------------------------------------------------
 * Extract Info.plist (top-level) from an .ipa using UnZipArchive
 * ---------------------------------------------------------------------- */
function getPlistFile(file) {
    return new Promise(function (resolve) {
        window.un = new UnZipArchive(file);
        un.getData(function () {
            var entries = un.getEntries();
            for (var i = 0; i < entries.length; i++) {
                var depth = entries[i].split('/').length - 1;
                if (entries[i].indexOf('/Info.plist') != -1 && depth == 2) {
                    console.log(entries[i]);
                    un.getData(entries[i], function (data) {
                        var plistFile = new window.File([data], 'Info.plist');
                        resolve(plistFile);
                    });
                }
            }
        });
    });
}
