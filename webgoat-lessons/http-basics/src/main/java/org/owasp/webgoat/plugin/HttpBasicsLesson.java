package org.owasp.webgoat.plugin;

import org.owasp.webgoat.assignments.AssignmentEndpoint;
import org.owasp.webgoat.assignments.AssignmentHints;
import org.owasp.webgoat.assignments.AssignmentPath;
import org.owasp.webgoat.assignments.AttackResult;
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
        String raw_input_string = raw_string;
        if (raw_input_string.isEmpty()) {
            return trackProgress(failed()
                    .feedback("http-basics.empty")
                    .feedbackArgs("empty string")
                    .build());
        }
        StringBuilder bld = new StringBuilder();
        for (int i=0; i<raw_input_string.length(); ++i) {
            bld.append(ENCSP);
            bld.append( raw_input_string.charAt(i));
            bld.append(ENCSP);
        }


        bld = new StringBuilder();
        for (int i=0; i<raw_input_string.length(); ++i) {
            bld.append(ENCSP);
            bld.append( raw_input_string.charAt(i));
            bld.append(ENCSP);
        }

        String str_1 = bld.toString();
        String htmlEscInputString = HtmlUtils.htmlEscape(bld.toString());
        String htmlEscInputString_1 = HtmlUtils.htmlEscape(str_1);

        String str_2 = "" + raw_input_string.charAt(0);
        String htmlEscInputString_2 = HtmlUtils.htmlEscape(str_2);

        String htmlEscInputString_3 = HtmlUtils.htmlEscape(bld.toString());

        byte[] raw_input_bytes = raw_input_string.getBytes();
        String hex_encoded_input_string = DatatypeConverter.printHexBinary(raw_input_bytes);
        String url_form_encoded_input = URLEncoder.encode(raw_input_string, "UTF-8");

        StringBuilder bld1 = new StringBuilder();
        StringBuilder bld2 = new StringBuilder();
        StringBuilder bld3 = new StringBuilder(); // copy of raw_input_string
        StringBuilder bld4 = new StringBuilder(); // copy of HtmlUtils.htmlEscape(raw_inoput_string)
        for (int i=0; i<raw_input_string.length(); ++i) {
            String currentChar = "" + raw_input_string.charAt(i);
            String htmlEscCurrentChar = HtmlUtils.htmlEscape(currentChar);
            bld1.append(htmlEscCurrentChar);

            bld3.append(raw_input_string.charAt(i));
            bld4.append(htmlEscCurrentChar);

            byte[] charBytes = currentChar.getBytes();
            String charBytesStr = DatatypeConverter.printHexBinary(charBytes);
            bld2.append(charBytesStr);

            int nPad = charBytesStr.length();
            while(0 < --nPad)
                bld1.append(ENCSP);

            bld1.append(ENCSP);
            bld2.append(ENCSP);
        }
        String new_formatted_input_string = bld1.toString();
        String new_hex_formatted_input_string = bld2.toString();

        String copy_1 = bld3.toString(); // copy of raw_input_string
        String copy_2 = bld4.toString(); // copy of HtmlUtils.htmlEscape(raw_input_string)
        String copy_3 = HtmlUtils.htmlEscape(raw_input_string) ;


        bld = new StringBuilder();
        for (int i=0; i<hex_encoded_input_string.length(); i=i+2) {
            bld.append( hex_encoded_input_string.substring(i,i+2));
            bld.append(ENCSP);
        }
        String hex_formatted_input_string = bld.toString();

        bld = new StringBuilder();
        for (int i=0; i<url_form_encoded_input.length(); ++i) {
            if (url_form_encoded_input.charAt(i) == '%') {
                bld.append(url_form_encoded_input.substring(i, i + 3));
                i = i + 2;
            } else {
                bld.append(ENCSP);
                bld.append(url_form_encoded_input.charAt(i));
                bld.append(ENCSP);
            }
        }
        String url_form_formatted_input_string = bld.toString();

        String feedbackArgs = "<br><div><br>" // HtmlUtils.htmlEscape(raw_input_string)
                + "<br>" + "<table border=1 style=font-family:monospace>"
                + "<tr>"
                + "<th>" + "Your input" // + "</th>"
                + "<td>" + HtmlUtils.htmlEscape(raw_input_string) // + "</td>"
                    // + "</tr>"
                + "<tr>"
                + "<th>" + "your input (spaces added for alignment)" // + "</th>"
                + "<td>" + new_formatted_input_string// + "</td>"
                // + "</tr>"
                + "<tr>"
                + "<th>" + "hex input (spaces added for alignment)" // + "</th>"
                + "<td>" + new_hex_formatted_input_string // + "</td>"
                // + "</tr>"
                + "<tr>"
                + "<th>" + "byte stream, formatted" // + "</th>"
                + "<td>" + hex_formatted_input_string // + "</td>"
                + "<tr>"
                + "<th>" + "UTF-8 byte stream in hex " // + "</th>"
                + "<td>" + hex_encoded_input_string // + "</td>"
/*                + "<tr>"
                    + "<th>" + "url-form-encoded" // + "</th>"
                    + "<td>" + url_form_encoded_input // + "</td>"
                    // + "</tr>"
                    + "<tr>"
                    + "<th>" + "url-form formatted" // + "</th>"
                    + "<td>" + url_form_formatted_input_string // + "</td>"
                    // + "</tr>"
                    + "<tr>"
                    + "<th>" + "html escaped" // + "</th>"
                    + "<td>" + HtmlUtils.htmlEscape(htmlEscInputString) // + "</td>"
                // + "</table>"
                */
                ;

            return trackProgress(success()
                    .feedback("http-basics.reversed")
                    .feedbackArgs(feedbackArgs)
                    .output("http-basics.lesson.success.output")
                    .outputArgs("", hex_encoded_input_string, url_form_encoded_input)
                .build());
    }

    @RequestMapping(method = RequestMethod.PUT)
    public
    @ResponseBody
    AttackResult completed_put(@RequestParam String person) throws IOException {
        if (person.toString().equals("")) {
            return trackProgress(failed().feedback("http-basics.empty").build());
        }

        String raw_input_string = "raw input";
        String new_formatted_input_string = "new_formatted_inout_string";
        String url_form_encoded_input = "url_form_encoded_input";
        String htmlEscInputString = "htmlEscInputString";
        String url_form_formatted_input_string = "url_form_formatted_input_string";

        String feedbackArgs = "<br><div><br>" // HtmlUtils.htmlEscape(raw_input_string)
                + "<br>" + "<table border=1 style=font-family:monospace>"
                + "<tr>"
                + "<th>" + "Your input" // + "</th>"
                + "<td>" + HtmlUtils.htmlEscape(raw_input_string) // + "</td>"
                // + "</tr>"
                + "<tr>"
                + "<th>" + "your input (spaces added for alignment)" // + "</th>"
                + "<td>" + new_formatted_input_string// + "</td>"
                + "<tr>"
                    + "<th>" + "url-form-encoded" // + "</th>"
                    + "<td>" + url_form_encoded_input // + "</td>"
                    // + "</tr>"
                    + "<tr>"
                    + "<th>" + "url-form formatted" // + "</th>"
                    + "<td>" + url_form_formatted_input_string // + "</td>"
                    // + "</tr>"
                    + "<tr>"
                    + "<th>" + "html escaped" // + "</th>"
                    + "<td>" + HtmlUtils.htmlEscape(htmlEscInputString) // + "</td>"
                // + "</table>"
                ;

        String hex_encoded_input_string = "hex_encoded_input_string";
        return trackProgress(success()
                .feedback("http-basics.reversed")
                .feedbackArgs(feedbackArgs)
                .output("http-basics.lesson.success.output")
                .outputArgs("", hex_encoded_input_string, url_form_encoded_input)
                .build());

    }
}
