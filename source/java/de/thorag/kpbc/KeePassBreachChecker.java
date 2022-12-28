/** 
 * Copyright (c) 2022, thorag
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. 
 **/

package de.thorag.kpbc;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Formatter;
import java.util.List;

import de.slackspace.openkeepass.KeePassDatabase;
import de.slackspace.openkeepass.domain.Entry;
import de.slackspace.openkeepass.domain.KeePassFile;

public class KeePassBreachChecker {

    protected static final String NL = System.lineSeparator();

    protected static final String API_URL = "https://api.pwnedpasswords.com/range/";
    
    protected boolean suppressPrintingOfPassword;

    protected boolean answerIsYes;

    public static void main(String[] args) throws Exception {
        new KeePassBreachChecker().start(args);
    }

    protected void start(String[] args) throws Exception {

        String kdbxFileLocation = null;
        for (String arg : args) {
            if (arg.startsWith("-")) {
                this.parseArg(arg);
            } else {
                kdbxFileLocation = arg;
            }
        }

        System.out.println("KeePassBreachChecker (c) 2022 by thorag");
        System.out.println();

        if (kdbxFileLocation == null) {
            System.out.println("Usage:");
            System.out.println("KeePassBreachChecker [Option] <KeePassDBFileLocation>");
            System.out.println();
            System.out.println("Options:");
            System.out.println("    -s    Suppress the display of passwords on the console.");
            System.out.println("    -y    Skip the input line and answer all questions with \"yes\"");
            System.exit(1);
        }
        this.showDisclaimer();
        this.processKeePassDB(kdbxFileLocation);
    }

    protected void parseArg(String arg) {

        if (arg.equals("-s")) {
            this.suppressPrintingOfPassword = true;
        } else if (arg.equals("-y")) {
            this.answerIsYes = true;
        }
    }

    protected void showDisclaimer() {

        System.out.println("Important Notice:");
        System.out.println("This software utilizes third party code. The author of " +
                "KeePassBreachChecker is not responsible for the code of any third party library " +
                "nor any builds of them. Use at own risk. If you are paranoid, just don't use it " +
                "or make sure to block all traffic except the one to the \"haveibeenpwned\" API. " +
                "Feel free to inspect my code and the code of the utilized third party libs and " +
                "do a build of the tool and the third party library on your own if you don't trust " +
                "the code. By using this software you submit to those conditions.");
        System.out.println();
        System.out.print("Do you agree? (yes/no): ");
        if (!this.answerIsYes) {
            String answer = System.console().readLine();
            if (!(answer.equalsIgnoreCase("y") || answer.equalsIgnoreCase("yes"))) {
                System.exit(0);
            }
        } else {
            System.out.println("y");
        }
        System.out.println();
    }

    protected void processKeePassDB(String kdbxFileLocation) throws Exception {

        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(1);
        }

        String pw = new String(console.readPassword("Enter password: "));
        try {
            
            KeePassFile database = KeePassDatabase.getInstance(kdbxFileLocation).openDatabase(pw);
            
            // Retrieve all entries
            List<Entry> entries = database.getEntries();
            for (Entry entry : entries) {
                if (this.checkBreach(entry.getPassword())) {
                    System.out.println("Entry title: " + entry.getTitle() + "| Entry URL: " + entry.getUrl()
                    + " | Entry login: " + entry.getUsername());
                    if (!this.suppressPrintingOfPassword) {
                        System.out.println(">>> Pwnd PW: " + entry.getPassword());
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Exception occured: " + e.getMessage());
        }
    }

    protected boolean checkBreach(String password) throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.reset();
        md.update(password.getBytes("UTF-8"));
        String sha1 = byteToHex(md.digest());
        String prefix = sha1.substring(0, 5);

        HttpURLConnection con = (HttpURLConnection) new URL(API_URL + prefix).openConnection();
        con.setRequestProperty("User-Agent",
                "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");
        con.setRequestMethod("GET");
        int status = con.getResponseCode();
        if (status == HttpURLConnection.HTTP_OK) {
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer content = new StringBuffer();
            while ((inputLine = in.readLine()) != null) {
                if ((prefix + inputLine.substring(0, inputLine.lastIndexOf(':'))).equalsIgnoreCase(sha1)) {
                    content.append(NL + "Full hash: " + prefix + inputLine + " hits" + NL);
                }
            }
            in.close();
            System.out.print(content);
            if (content.length() > 0) {
                return true;
            }
        }
        return false;
    }

    protected String byteToHex(final byte[] hash) {

        Formatter formatter = new Formatter();
        for (byte b : hash) {
            formatter.format("%02x", Byte.valueOf(b));
        }
        String result = formatter.toString();
        formatter.close();
        return result;
    }
}
