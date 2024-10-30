Laran is a Go script for BBH and Pentesters , useful to sift through large lists of URLS (EG:katana,Gospider,GAU output) for injectable params (XSS,SQLI,LFI,RCE etc.) and sensitive files (databases,backups,secrets,creds,keys)

Usage: laran [options]

Options:

  -h, --help        Display help
  
  -l, --list        Display list of potential exposed file extensions
  
  -f, --files       Specify file extension(s) to search for, e.g., -f conf,txt
  
  -vt, --vector     Specify vector(s) to check, e.g., -vt xss,sqli
  
  --type            Specify type to filter, e.g., --type log,ide,office,app,code,backup,hidden,database,source,creds,pass,conf


Example:

cat urls.txt | laran --type log


  Potentially exposed file extensions:

Other Sensitive Files:
  passwd, shadow, mobileconfig, keytab

Additional Extensions from Original Code:
  bkp, cache, html, inc, lock, rar, tar, tar.bz2, tar.gz, txt, wadl, zip

Log and Dump Files:
  log, out, err, trace, dump

Source Code and Script Files:
  php, php~, py, py~, pyc, jsp, asp, asp~, aspx, aspx~, pl, rb, rb~, cgi, sh, bash, zsh, c, cpp, cs, java, class, jar, war, js, ts, go, swift, kt, scala, vb

Credentials, Keys, and Certificate Files:
  pem, key, crt, cer, der, pfx, p12, jks, keystore, ovpn, rdp, ppk, id_rsa, id_rsa.pub, ssh, gpg, pgp, kdb, kdbx, keychain, sso, secrets

Editor and IDE Project Files:
  swp, swp~, swo, idea, vscode, sublime-project, sublime-workspace, project, classpath, metadata, iml

Office Documents and Data Files:
  doc, docx, xls, xlsx, ppt, pptx, pdf, csv

Application and Package Files:
  apk, ipa, exe, dll, so, dmg, iso, img, app, deb, rpm

Backup and Temporary Files:
  bak, bak~, backup, old, orig, save, tmp, temp, copy, ~

Configuration and Environment Files:
  conf, config, cfg, ini, env, properties, xml, json, yml, yaml, toml, plist

Database Files and Dumps:
  sql, sql~, sql.gz, sql.tar.gz, sql.zip, db, db3, sqlite, sqlite3, mdb, accdb, ldf, mdf

Hidden Files and Directories:
  git, svn, hg, bzr, htaccess, htpasswd, DS_Store, npmrc, dockerignore, dockercfg, dockerconfigjson, netrc, bash_history, zsh_history, history
