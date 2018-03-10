package org.owasp.webgoat.plugin;

import org.owasp.webgoat.assignments.AssignmentEndpoint;
import org.owasp.webgoat.assignments.AssignmentHints;
import org.owasp.webgoat.assignments.AssignmentPath;
import org.owasp.webgoat.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.net.URLEncoder;

/**
 * *************************************************************************************************
 * <p>
 * <p>
 * This file is part of WebGoat, an Open Web Application Security Project
 * utility. For details, please see http://www.owasp.org/
 * <p>
 * Copyright (c) 2002 - 20014 Bruce Mayhew
 * <p>
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 * <p>
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307, USA.
 * <p>
 * Getting Source ==============
 * <p>
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository
 * for free software projects.
 * <p>
 * For details, please see http://webgoat.github.io
 *
 * @author Bruce Mayhew <a href="http://code.google.com/p/webgoat">WebGoat</a>
 * @created October 28, 2003
 */
@AssignmentPath("/HttpBasics/attack1")
@AssignmentHints({"http-basics.hints.http_basics_lesson.1"})
public class HttpBasicsLesson extends AssignmentEndpoint {

    public static final char ENCSP = '.'; // display spaces/separators in encoded strings

    @RequestMapping(method = RequestMethod.GET)
    public
    @ResponseBody
    AttackResult completed(@RequestParam String raw_string) throws IOException {
        if (raw_string.isEmpty()) {
            return trackProgress(failed()
                    .feedback("http-basics.empty")
                    .feedbackArgs("empty string")
                    .build());
        }

        // purpose is to show how the raw string input gets encoded into UTF-8
        // example, user input "<1>  build the following strings
        // raw in     = "<1>"
        // rawF       = "<  1  >"
        // enc        = "3C 31 3E"
        // outputO    = 3C313E"

        String rawIn       = raw_string;
        StringBuilder rawF_SB     = new StringBuilder();
        StringBuilder enc_SB      = new StringBuilder();
        StringBuilder outputO_SB  = new StringBuilder();

        for (int i=0; i<rawIn.length(); ++i) {
            String currChar = rawIn.substring(i, i+1);
            String htmlEscCurrentChar = HtmlUtils.htmlEscape(currChar);
            rawF_SB.append(htmlEscCurrentChar); // always esc when displaying raw input

            // the character representation may be more than one byte
            byte[] currCharEncSeq = currChar.getBytes("UTF-8");
            for(byte b : currCharEncSeq) {
                String str = String.format("%02x", b);
                enc_SB.append(str);
                enc_SB.append(ENCSP);
                outputO_SB.append(str);
            }
            // each byte gets three chars output, two hex and one sp
            // index starts at 1, already one chara output
            for(int j=1; j< (3*currCharEncSeq.length); ++j) {
                rawF_SB.append(ENCSP);
            }
        }
        String rawF = rawF_SB.toString();
        String enc = enc_SB.toString();
        String outputO = outputO_SB.toString();

        String feedbackArgs = "<br>"
                + "<br>" + "<table border=1 style=font-family:monospace>"
                + "<tr>"
                + "<th>" + "Your input" + "</th>"
                + "<td>" + HtmlUtils.htmlEscape(rawIn) + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "split up into chars" + "</th>"
                + "<td>" + rawF + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "UTF-8 hex " + "</th>"
                + "<td>" + enc + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "byte stream" + "</th>"
                + "<td>" + outputO + "</td>"
                + "</tr>"
                + "</table> ";

            return trackProgress(success()
                    .feedback("http-basics.encoding.get.feedback")
                    .feedbackArgs(feedbackArgs)
                    .output("http-basics.lesson.success.output")
                    .outputArgs("", "", "")
                .build());
    }

    @RequestMapping(method = RequestMethod.PUT)
    public
    @ResponseBody
    AttackResult completed_put(@RequestParam String raw_string) throws IOException {

        // purpose is to show how the raw string input gets encoded into url-form-encoded
        // URLEncoder.encode() implements url-form-encode,
        // this code explains that algorithm, together with UTF-8
        String rawInputString = raw_string;

        // the input string, as entered, formatted for display in html
        String htmlEscInputString = HtmlUtils.htmlEscape(rawInputString);

        // content-type = url-form-encoded
        String url_form_encoded_input = URLEncoder.encode(rawInputString, "UTF-8");

        // encode the input string, character at a time,
        // and produce the intermediate calculations for display
        // example:
        // raw input  = "<1>"
        // raw enc    = "%3C1%3E"
        // rawEncF    = "<   1 >"
        // enc        = "%3C 1 %CE"
        // encCh      = "%3C 1 %3E"
        // encChars   = "% 3 C 1 % 3 E"
        // encCharsF  = "<        1 >      "
        // encCharsFF = "%  3  C  1 %  3  E"
        // encCharsO  = "?? 33 43 31 ?? 31 45"
        // outputO    = "??334331??3145"
        StringBuilder rawEnc_SB = new StringBuilder();
        StringBuilder rawEncF_SB = new StringBuilder();
        StringBuilder enc_SB = new StringBuilder();
        StringBuilder encCh_SB = new StringBuilder();
        StringBuilder encCharsFF_SB = new StringBuilder();
        StringBuilder encCharsO_SB= new StringBuilder();
        StringBuilder outputO_SB = new StringBuilder();
        for (int i=0; i<rawInputString.length(); ++i) {
            String currChar = rawInputString.substring(i, i + 1);
            String currCharEnc = URLEncoder.encode(currChar, "UTF-8");
            enc_SB.append(currCharEnc);
            enc_SB.append(ENCSP);
            int len = currCharEnc.length();
            for (int j = 0; j < len; ++j) {
                String str = currCharEnc.substring(j, j + 1);
                encCharsFF_SB.append(str);
                encCharsFF_SB.append(ENCSP);
                encCharsFF_SB.append(ENCSP);
                byte xx = (byte) currCharEnc.charAt(j);
                String sxx = String.format("%02x", xx);
                encCharsO_SB.append(sxx);
                encCharsO_SB.append(ENCSP);
                outputO_SB.append(sxx);
            }
            rawEncF_SB.append(HtmlUtils.htmlEscape(currChar));
            rawEncF_SB.append(ENCSP);
            len = currCharEnc.length();
            while (0 < --len) {
                rawEncF_SB.append(ENCSP);
            }
        }

        String enc = enc_SB.toString();
        String rawEncF = rawEncF_SB.toString();
        String encCharsFF = encCharsFF_SB.toString();
        String encCharsO = encCharsO_SB.toString();
        String outO = outputO_SB.toString();

        String feedbackArgs = "<br><div><br>" // HtmlUtils.htmlEscape(raw_input_string)
                + "<br>" + "<table border=1 style=font-family:monospace>"
                + "<tr>"
                + "<th>" + "Your input" + "</th>"
                + "<td>" + HtmlUtils.htmlEscape(rawInputString) + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "is split into chars" + "</th>"
                + "<td>" + rawEncF + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + " each char is url-form-encoded"  + "</th>"
                + "<td>" + enc + "</td>"
                + "</tr>"
         /* ** PJH remove      + "<tr>"
                + "<th>" + "encoded string is split into chars"  + "</th>"
                + "<td>" + url_form_encoded_input  + "</td>"
                + "</tr>" */
                + "<tr>"
                + "<th>" + "url_form_encoded_bytes " + "</th>"
                + "<td>" + encCharsFF + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "  octet hex values " + "</th>"
                + "<td>" + encCharsO + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "output byte stream" + "</th>"
                + "<td>" + outO + "</td>"
                + "</tr>"
                + "</table>"
                + "<br>"
                + "input was " + rawInputString.length() + " display characters "
                + rawInputString.length() + " bytes in memory "
                + url_form_encoded_input .length() + " bytes to send in http"
                ;
        return trackProgress(success()
                .feedback("http-basics.encoding.post.feedback")
                .feedbackArgs(feedbackArgs)
                .output("http-basics.lesson.success.output")
                .outputArgs("After trying a few strings, go to the next page" )
                .build());

    }
}
