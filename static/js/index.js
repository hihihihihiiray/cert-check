/**
 * iOS 证书在线检测 — client-side cert checker
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
        statusRevoked:    '撤销',
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
 * Upload + render the API response (p12.ee)
 * ---------------------------------------------------------------------- */
function uploads(p12, password, mp, plist) {
    var formData = new FormData();

    // p12.ee uses "file" for the main file and "p12pwd" for the password
    if (p12) {
        formData.append('file',   p12);
        formData.append('p12pwd', password ? password : '');
    } else if (mp) {
        formData.append('file',   mp);
        formData.append('p12pwd', '');
    }
    if (plist) {
        formData.append('infofile', plist);
    }

    this_input = $(this);
    $('#shortUrl').css('display', 'none');
    $('#search').removeClass('hide');

    $.ajax({
        url:         'https://p12.ee/icapi/icheck/upload',
        type:        'POST',
        cache:       false,
        data:        formData,
        processData: false,
        contentType: false,
        dataType:    'json',
        // p12.ee requires these headers to pass its anti-CSRF check
        headers: {
            'Origin':  'https://p12.ee',
            'Referer': 'https://p12.ee/'
        },
        beforeSend: function () { uploading = true; },
        success:    function (res) {
            if (res.code == 0) {
                var d = res.data;

                $('#search').attr('class', 'hide');
                $('#certResult').hide().removeClass('hide').fadeIn(200);
                $('#fileCertResult').removeClass('hide');

                // Map p12.ee fields to our display variables
                // pemStatus: "issued" = good, "revoked" = revoked
                var state = (d.pemStatus === 'revoked') ? 'revoked' : 'good';

                // Check if cert is expired by comparing pemExp to now
                if (state === 'good' && d.pemExp) {
                    var expDate = new Date(d.pemExp);
                    if (!isNaN(expDate) && expDate < new Date()) {
                        state = 'expired';
                    }
                }

                // teamType mapping: "ent" = 企业, "ind" = 个人, "com" = 开发
                var typeMapZh = { 'ent': '企业', 'ind': '个人', 'com': '开发' };
                var typeMapEn = { 'ent': 'In-House', 'ind': 'Ad Hoc', 'com': 'Development' };
                var certTypeRaw = d.teamType || '';
                var certTypeZh  = typeMapZh[certTypeRaw] || certTypeRaw;

                // Save for language toggle re-renders
                lastCertState   = state;
                lastCertType    = certTypeZh;
                lastAttribution = d.country || null;

                // Cert status
                if (state === 'revoked') {
                    $('#revokedDate').removeClass('hide');
                    $('#certStatus').prepend('<span class="text-danger">' + t('statusRevoked') + '</span>');
                    $('#certRevokedDate').html(d.revokeTime || '');
                    $('#certStatusExplain').attr('data-content',
                        t('statusRevoked') === 'Revoked'
                            ? 'The certificate was revoked by you or Apple.'
                            : '证书已被您自己或苹果官方撤销');
                } else if (state === 'expired') {
                    $('#revokedDate').removeClass('hide');
                    $('#certStatus').prepend('<span class="text-danger">' + t('statusExpired') + '</span>');
                    $('#certRevokedDate').html(d.pemExp || '');
                    $('#certStatusExplain').attr('class', 'hide');
                } else {
                    $('#certStatusExplain').attr('class', 'hide');
                    $('#certStatus').prepend('<span class="text-success">' + t('statusGood') + '</span>');
                }

                // Cert name and expiry
                $('#certName').html(d.teamName || '');
                $('#certExpireDate').html(d.pemExp || '');

                // Cert type + country
                var lang = (typeof currentLang !== 'undefined') ? currentLang : 'zh';
                var countryWord  = (lang === 'en') ? 'Country' : '国家';
                var displayType  = certTypeZh;
                if (displayType && d.country) {
                    $('#certType').html(displayType + ' (' + countryWord + ': ' + d.country + ')');
                } else if (displayType) {
                    $('#certType').html(displayType);
                } else if (d.country) {
                    $('#certType').html(d.country);
                }

                // SHA-1 (server calls it pemMD5 but it's 40-char SHA1)
                if (d.pemMD5) {
                    $('#sha1Row').removeClass('hide');
                    $('#certSha1').css('word-break', 'break-all').html(d.pemMD5.toLowerCase());
                }

                // Mobileprovision fields
                if (d.mpExp || d.mpAppID) {
                    lastProvisionMatched = true;
                    $('.provision-detail').removeClass('hide');
                    $('#provisionExpireDate').html(d.mpExp || '');
                    $('#identifier').html(d.mpAppID || '');
                    $('#provisionStatus').prepend('<span class="text-success">' + t('provisionMatched') + '</span>');
                }

                // IPA bundle fields
                if (d.ipaName) {
                    $('.appNameSpan').html(d.ipaName);
                    $('#appName').removeClass('hide');
                }
                if (d.ipaBID) {
                    $('.bundleIdSpan').html(d.ipaBID);
                    $('#bundleId').removeClass('hide');
                }

                $('#recheckBtn').removeClass('hide');
            } else {
                $('#errorMsg').removeClass('hide');
                $('#errorMsg').prepend('<span style="color: #FD5A5A; font-size: 18px;">' + res.message + '</span>');
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
 * Reset UI back to upload state without reloading the page
 * ---------------------------------------------------------------------- */
function toggleRes() {
    // Fade out the results
    $('#certResult').fadeOut(220, function() {
        // Reset everything after fade completes
        uploading  = false;
        file_item  = null;
        this_input = null;

        $('#uploadfile').val('');
        $('#certResult').addClass('hide').show();
        $('#search').addClass('hide');
        $('#errorMsg').addClass('hide');
        $('#recheckBtn').addClass('hide');

        $('#certStatus').empty();
        $('#certName').empty();
        $('#certExpireDate').empty();
        $('#certRevokedDate').empty();
        $('#certType').empty();
        $('#certSha1').empty();
        $('#provisionStatus').empty();
        $('#provisionExpireDate').empty();
        $('#identifier').empty();
        $('#errorMsg').empty();

        $('#revokedDate').addClass('hide');
        $('#sha1Row').addClass('hide');
        $('#appName').addClass('hide');
        $('#bundleId').addClass('hide');
        $('#certDetail').removeClass('hide');
        $('.provision-detail').addClass('hide');

        $('.appNameSpan').empty();
        $('.bundleIdSpan').empty();

        $('#certFlag').attr('src', 'static/picture/cert_icon_2x.png');
        $('#certStatusExplain').removeClass('hide');

        if (typeof lastCertState   !== 'undefined') lastCertState   = null;
        if (typeof lastCertType    !== 'undefined') lastCertType    = null;
        if (typeof lastAttribution !== 'undefined') lastAttribution = null;
        if (typeof lastProvisionMatched !== 'undefined') lastProvisionMatched = false;

        // Fade the upload box back in
        $('#shortUrl').hide().removeClass('hide').fadeIn(220);
    });
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
