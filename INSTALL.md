# Installing the passkey authentication class

For OpenText Access Manager (NAM) 26.2 / 5.1.3 Identity Servers. This is an independent project, not an OpenText product, and OpenText doesn't support it; see the [README](README.md). Configuration of the class, its methods and contracts is in the [README](README.md); this covers getting the files onto the servers.

## What gets installed

| File in the bundle | Goes to, on every Identity Server node | Owner, mode |
|---|---|---|
| `lib/nam-passkey-auth.jar` | `/opt/novell/nam/idp/webapps/nidp/WEB-INF/lib/nam-passkey-auth.jar` | `novlwww:novlwww`, 664 |
| `jsp/passkey_*.jsp`, `jsp/passkey_common.jspf` | `/opt/novell/nam/idp/webapps/nidp/jsp/` | `novlwww:novlwww`, 664 |
| `schema/edir-passkey.ldif` | Optional, applied once to eDirectory, not to the nodes. See [Schema](#schema-optional) | |

`/opt/novell/nam/idp/webapps/nidp` is a symlink to `/opt/novell/nids/lib/webapp`, which is the path the Advanced File Configurator shows. They're the same directory.

The Identity Server must be restarted to load a new or changed jar. JSP changes take effect without a restart.

Nothing else goes on the nodes. Every setting, including `RECOVERY_PEPPER`, is a class or method property in Administration Console, so NAM distributes it.

## The release bundle

`mvn package` builds `target/nam-passkey-auth-<version>-bundle.zip` (and the same as `.tar.gz`) next to the jar. See [docs/BUILDING.md](docs/BUILDING.md) for the one-time setup of the NAM jars. The bundle holds:

```
nam-passkey-auth-<version>/
  install.sh                 single-node installer (below)
  INSTALL.md                 this file
  VERSION
  LICENSE                    MIT
  THIRD-PARTY-NOTICES.txt    licenses of the libraries bundled in the jar
  lib/nam-passkey-auth.jar   the shaded jar, already named as it is on the server
  jsp/passkey_*.jsp, passkey_common.jspf
  schema/edir-passkey.ldif
```

## Choosing a method

| Deployment | Use |
|---|---|
| A cluster of Identity Servers | [Advanced File Configurator](#cluster-advanced-file-configurator) |
| Docker / Kubernetes | [Advanced File Configurator](#docker-and-kubernetes), or a derived image |
| One Identity Server, a lab, or a node not managed through AFC | [`install.sh`](#single-node-installsh) |

AFC is NAM's supported way to customise an Identity Server from 5.0 on. It pushes the files to every node in the cluster, applies them to nodes added later, keeps them across NAM upgrades, and in containers puts them back each time a pod starts. Use `install.sh` where those don't matter.

Pick one method per cluster. If AFC tracks a file, it overwrites any copy `install.sh` put there the next time it sends configuration, and AFC's **Remove Configurations** deletes the file from every node.

## Single node: install.sh

Run it as root on the Identity Server, from the unpacked bundle:

```bash
scp target/nam-passkey-auth-<version>-bundle.zip root@idp-host:/tmp/
ssh root@idp-host
cd /tmp && unzip -o nam-passkey-auth-<version>-bundle.zip && cd nam-passkey-auth-<version>
./install.sh --dry-run
./install.sh --restart
```

`--dry-run` lists each file as `add`, `replace`, `fix` (wrong owner or mode), `ok` or `remove`, and prints the commands it would run, changing nothing. Run it before anything else.

What an install does:

1. Checks that this is an Identity Server node: the webapp, `WEB-INF/lib/nidp.jar`, and a `novell-idp` init script or systemd unit. It also checks that `novlwww` exists. `--force` skips the node checks, for example inside a container image build.
2. Compares each file with the bundle. If everything matches, it changes nothing, so running it again is safe.
3. Copies whatever it's about to replace or remove to `/root/nam-passkey-auth-backup/<timestamp>/`, and notes which files didn't exist before.
4. Copies each new or changed file beside its target, sets `novlwww:novlwww` and 664, and renames it into place, so Tomcat never reads a half-written jar. On SELinux systems it then runs `restorecon` on them.
5. Removes files an earlier version installed that this one doesn't ship, and any other `WEB-INF/lib/nam-passkey-auth*.jar`, such as a versioned copy from a manual install. Two copies of the class on the classpath would make which one loads unpredictable.
6. Records the version and file list in `/root/nam-passkey-auth-backup/installed.list`.
7. With `--restart`, restarts the Identity Server through `systemctl restart novell-idp.service` if the unit exists, otherwise `/etc/init.d/novell-idp restart`. That takes about a minute. Without it, the script tells you to restart when the jar changed.

Other actions:

| Command | Does |
|---|---|
| `./install.sh --status` | Compares the installed files with this bundle and shows the installed jar's version. Changes nothing |
| `./install.sh --list-backups` | Lists the backups with what each was taken before |
| `./install.sh --rollback [ID] --restart` | Puts back the files saved in backup `ID`, and removes the ones that didn't exist then. With no `ID`, uses the newest install or uninstall backup. Running it twice gives the same result |
| `./install.sh --uninstall --restart` | Backs up and removes the jar and JSPs |

Every action that changes files takes its own backup first, a rollback included, so any of them can be undone. `--nidp-dir`, `--backup-dir` and `--owner` change the defaults; `./install.sh --help` lists everything. The script works with the bash and tools on SLES 12+ and RHEL 7+.

After a NAM upgrade, run `./install.sh --status`. The upgrade replaces the webapp's JSPs and may drop files it didn't ship, so if anything shows as `missing` or `differs`, run `./install.sh --restart` again from the same bundle.

## Cluster: Advanced File Configurator

These steps follow the AFC chapter of the NAM 26.2 Administer guide (§1.1.5). Add each file individually. **Never upload the `jsp` folder as a folder**: AFC replaces a folder on the servers completely, so every stock NAM page would be deleted.

Add the jar:

1. In Administration Console, on the Home page, click **Advanced File Configurator**, then the **Identity Server** tab.
2. Click **+** and choose **Upload Configurations**.
3. Set **Type** to **File**, **File Path** to `/opt/novell/nids/lib/webapp/WEB-INF/lib`, and choose the Identity Server cluster.
4. Under **Source**, browse to `lib/nam-passkey-auth.jar` from the bundle.
5. Turn on **Restart Identity Server**. Leave **Temporary Modification** off, so the file is kept across NAM upgrades. Set **Modification Type** to something you can search for, such as `Passkey authentication`, and put the bundle version in **Description**.
6. Click **OK**.

Add each JSP the same way, with **File Path** `/opt/novell/nids/lib/webapp/jsp`: `passkey_codes.jsp`, `passkey_common.jspf`, `passkey_gate.jsp`, `passkey_helpdesk.jsp`, `passkey_login.jsp`, `passkey_manage.jsp`, `passkey_mfa.jsp`, `passkey_recovery.jsp` and `passkey_register.jsp`. They don't need **Restart Identity Server**. The bundle's `jsp/` folder is the authoritative list for each version.

Then apply them:

1. Expand the cluster, select the jar and the JSPs, and click **Send Configurations to Servers**.
2. AFC says the jar needs a restart. Go to **Identity Servers** and click **Update All** with **Custom Files Configuration** selected. Each node restarts.
3. Check that each file's status is **Configuration sent successfully**, and that the Identity Servers come back green.

AFC keeps the permissions a file had on your computer, so upload them as unpacked from the bundle (readable by everyone). If a page or the class fails to load on a node, check the file's owner and mode there; `novlwww` must be able to read it.

To copy the setup to another cluster or environment, such as test to production, use **More Options > Export Configurations** on the source cluster and **More Options > Import Configurations** on the target, mapping the clusters. That carries all ten files, and any other AFC files on that cluster, in one step.

**Upgrading the passkey class.** For each file, click it in AFC, choose **Replace with New File**, upload the new version and click **OK**. Replace all ten. It's simpler than working out which changed, and AFC's **File Editor** can compare them with a node's copy if you want to. If a new version adds a JSP, add it as above. If it drops one, remove that entry. Then **Send Configurations to Servers** and **Update All**.

**Rolling back.** Keep the previous bundle. Replace the files with the previous version's, then send and **Update All** as for an upgrade. See [Rolling back](#rolling-back) for properties.

**Uninstalling.** Delete the Contracts, Methods and Class that use the class first, and update the Identity Servers. Then select the ten files in AFC and click **Remove Configurations**. Files NAM didn't ship are deleted from every node. **Update All** when prompted. **Untrack Configurations** instead stops AFC managing the files but leaves them on the nodes, and new nodes won't get them.

**After a NAM upgrade.** Follow the guide's post-upgrade steps (§1.1.5.2.9): for each AFC file, compare it with a node's copy in **File Editor**, click **Send Configurations to Servers** on all of them even if they show as sent, and **Update All**. Rebuild and upgrade the passkey class too if [CHANGELOG.md](CHANGELOG.md) or the [release notes](https://github.com/PointBlueTechnology/access-manager-passkey/releases) say the new NAM version needs it.

## Docker and Kubernetes

Use AFC, with the same steps as for a cluster. It's the supported way, and the only one that survives a pod restart without changing the image:

- An Identity Server pod's filesystem is rebuilt from the image every time the pod starts, so a file copied in with `kubectl cp` or `install.sh` is lost on the next restart.
- AFC keeps the files it manages on the Identity Server's persistent volume (`/opt/novell/nam/docker/custom_volume`, the chart's `custom/other_customization`), with their paths listed in `custom/lists`. The pod's startup script copies them back into place before starting Tomcat. That includes new replicas and pods on a new NAM image.

This is how the 5.1.3 Helm chart (1.3.0) and the `am-idp:5.1.3.0-162` image do it; it hasn't been run on a cluster for this project yet.

The guide's way to restart a containerised Identity Server, if **Update All** doesn't, is:

```bash
kubectl get pods --namespace <namespace>
kubectl exec --namespace <namespace> -it pod/<identity-server-pod> -- sh -c '/etc/init.d/novell-idp restart'
```

Restart each Identity Server pod in turn.

**Alternative: a derived image.** If images must be built in a pipeline and nothing may be changed through the console, bake the files into the image instead:

```dockerfile
FROM <your-registry>/am-idp:5.1.3.0-162
COPY --chown=novlwww:novlwww nam-passkey-auth-<version>/lib/nam-passkey-auth.jar /opt/novell/nids/lib/webapp/WEB-INF/lib/
COPY --chown=novlwww:novlwww nam-passkey-auth-<version>/jsp/ /opt/novell/nids/lib/webapp/jsp/
RUN chmod 664 /opt/novell/nids/lib/webapp/WEB-INF/lib/nam-passkey-auth.jar /opt/novell/nids/lib/webapp/jsp/passkey_*
```

The chart builds the image name as `<global.image.repository>/am-idp:<chart appVersion>`, so push the result to your own registry under that same name and tag and set `global.image.repository` to it. Keep the stock image under another name. You then rebuild for every NAM image update and every passkey release. Don't also manage these files through AFC: its copies are restored over the image's at each start. OpenText support may ask for the stock image when you raise a case.

## Configure the class

Once the files are on every node, set up the class in Administration Console: **Identity Servers > Edit > Local > Classes > New**, **Other**, Java class `com.pointbluetech.nam.login.passkey.PasskeyAuthClass`, then its properties, Methods and Contracts. The [README](README.md#configuration) lists every property. Configuration is stored by NAM, so it doesn't need reinstalling with the files.

## Schema (optional)

The class works with the default `carLicense` attribute and no schema change. For production, `schema/edir-passkey.ldif` adds dedicated attributes and the `pbtPasskeyUser` auxiliary class to eDirectory. It needs no OIDs: eDirectory takes the `<name>-oid` form the file uses. Apply it once per tree, not per node, as an administrator with schema rights:

```bash
ldapmodify -H ldaps://edir.example.com -D cn=admin,o=system -W -f schema/edir-passkey.ldif
```

`install.sh` doesn't do this. See the README's [Schema](README.md#schema) section for the access rights and properties to set afterwards.

## Upgrading

1. Read [CHANGELOG.md](CHANGELOG.md) for new or changed properties.
2. Install the new files: AFC **Replace with New File** for each file, or `./install.sh --dry-run` and then `./install.sh --restart` from the new bundle.
3. Restart the Identity Servers (AFC's **Update All**, or `--restart`). Every node must run the same version, because a sign-in can move between nodes mid-ceremony.
4. Check `catalina.out` for `[Passkey]` lines. Each method logs `PasskeyAuthClass <version> initialized` with its settings when first used. An invalid configuration logs `PasskeyAuthClass INIT FAILED`, followed by every problem in one warning.

Stored passkeys, recovery codes and configuration aren't touched by an upgrade.

## Rolling back

- `install.sh`: `./install.sh --rollback --restart` puts back the files from before the last install. `--list-backups` shows the others.
- AFC: replace the files with the previous bundle's, send, and **Update All**.

Older versions ignore properties they don't know. A value they don't accept, such as a new choice in an existing property, makes the class fail to load with a warning naming the property, so set those back to what the older version supports.
