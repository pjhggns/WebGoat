package org.owasp.webgoat.plugin;

import org.owasp.webgoat.assignments.AssignmentEndpoint;
import org.owasp.webgoat.assignments.AssignmentHints;
import org.owasp.webgoat.assignments.AssignmentPath;
import org.owasp.webgoat.assignments.AttackResult;
import org.owasp.webgoat.i18n.PluginMessages;
import org.owasp.webgoat.session.UserSessionData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;
import java.net.URLEncoder;

/**
 * *************************************************************************************************
 * <p>
 * <p>
 * *************************************************************************************************
 */

@AssignmentPath("/HttpBasics/encoding")
@AssignmentHints({"http-basics.hints.http_basics_lesson.1"})
public class HttpBasics_encoding2 extends AssignmentEndpoint {

    @Autowired
    UserSessionData userSessionData;
    @Autowired
    private PluginMessages pluginMessages;

    public static final char ENCSP = '.'; // display spaces/separators in encoded strings


    @RequestMapping(value="/utf8", method = RequestMethod.GET)
    public
    @ResponseBody
    AttackResult handlerUTF8Get(@RequestParam String input_string) throws IOException {
        if (input_string.isEmpty()) {
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

        String rawIn       = input_string;
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
        String totals = pluginMessages.getMessage("http-basics.encoding.get.output",
                input_string.length(), outputO.length());

        TableDiaplayBuilder bldr = new TableDiaplayBuilder();
        String feedbackArgs = bldr
                .addRow("Your input", HtmlUtils.htmlEscape(rawIn))
                .addRow( "split up into chars", rawF )
                .addRow("UTF-8 hex " ,enc )
                .addRow( "byte stream" , outputO )
                .addRow("total", totals)
                .build();

        return trackProgress(success()
                .feedback("http-basics.encoding.get.feedback")
                .feedbackArgs(feedbackArgs)
                .output("http-basics.lesson.success.output")
                .outputArgs("", "", "")
                .build());
    }

    @RequestMapping(value="/utf8", method = RequestMethod.PUT)
    public
    @ResponseBody
    AttackResult handlerUTF8Put(@RequestParam String input_string) throws IOException {

        // purpose is to show how the raw string input gets encoded into url-form-encoded
        // URLEncoder.encode() implements url-form-encode,
        // this code explains that algorithm, together with UTF-8
        String rawInputString = input_string;

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
        String totals = "input was " + rawInputString.length() + " display characters "
                + url_form_encoded_input .length() + " bytes to send in http";

        TableDiaplayBuilder bldr = new TableDiaplayBuilder();
        String feedbackArgs = bldr
                .addRow("Your input" , HtmlUtils.htmlEscape(rawInputString) )
                .addRow("is split into chars", rawEncF)
                .addRow("each char in url-form-encoded", enc)
                .addRow("each char in url-form-encoded bytes", encCharsFF)
                .addRow("octet hex values", encCharsO)
                .addRow("output byte Stream", outO)
                .addRow("totals", totals)
                .build();

        return trackProgress(success()
                .feedback("http-basics.encoding.post.feedback")
                .feedbackArgs(feedbackArgs)
                .output("http-basics.lesson.success.output")
                .outputArgs("After trying a few strings, go to the next page" )
                .build());

    }

    static final String lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/";


    @RequestMapping(value="/base64", method = RequestMethod.POST)
    public
    @ResponseBody
    AttackResult handlerBase64Post(@RequestParam String input_string) throws IOException {

        // encode the input string treated as a binary number
        // and produce the intermediate calculations for display
        // example:
        // raw input  = "FFF000"
        // rawF       = "FF F0 00"
        // rawBinF    = "FF        F0        00"
        // inpBin     = "1111 1111 1111 0000 0000 0000"
        // binEnc     = "111111 111111 000000 000000"
        // encDec     = "63     63     00     00"
        // encChars   = "/      /      A      A"
        // outChars   = "/  /  A  A"
        // outputO    = "2F @F 41 41"
        // encChars   = "/ / A A"
        // outBase64  = "//AA"

        // encChURL   = "_  _  A  A"

        StringBuilder raw_SB = new StringBuilder();
        StringBuilder rawF_SB = new StringBuilder();
        StringBuilder rawBinF_SB = new StringBuilder();
        StringBuilder inpBin_SB = new StringBuilder();
        StringBuilder binEnc_SB = new StringBuilder();
        StringBuilder encDec_SB = new StringBuilder();
        StringBuilder encChars_SB = new StringBuilder();
        StringBuilder encCharsF_SB = new StringBuilder();
        StringBuilder outChars_SB = new StringBuilder();
        StringBuilder out_SB = new StringBuilder();
        StringBuilder outputO_SB = new StringBuilder();
        StringBuilder outBase64_SB = new StringBuilder();

        // first, fixup the input for valid hex.
        String inp = input_string.replaceAll("[^A-Fa-f0-9]", "");
        if (inp.length() % 2 != 0)
            inp = inp + "0";
        // TODO: tell user string was changed

        // round the input up and fixup the end chara later
        int fixupLen = inp.length()  % 3;
        for (int j=0; j<fixupLen; ++j)
            inp += "00";

        // build the output strings, chunk at a time
        for (int i=0; i<inp.length(); i=i+6) {
            // TODO: This code is horrible
            String strS[] = new String[3];
            String hexS[] = new String[3];
            String decS[] = new String[3];
            int hexN[] = new int[3];

            for (int j = 0; j < 3; ++j) {
                int x = i + j * 2;
                strS[j] = inp.substring(x, x + 2);
                hexN[j] = Integer.parseInt(strS[j], 16);
                rawF_SB.append(strS[j] + ENCSP);
                inpBin_SB.append(asBinStr(8, hexN[j]) + ENCSP);
            }

            int chunk[] = new int[4];
            chunk[0] = (hexN[0] & 0x00fC) >> 2;
            chunk[1] = ((hexN[0] & 0x03) << 4) + ((hexN[1] & 0x00f0) >> 4);
            chunk[2] = ((hexN[1] & 0x0f) << 2) + ((hexN[2] & 0x00c0) >> 6);
            chunk[3] = hexN[2] & 0x3f;

            for (int j = 0; j < chunk.length; ++j) {
                int ch = chunk[j];
                encChars_SB.append(Integer.toString(ch, 16) + ENCSP);
                encDec_SB.append(Integer.toString(ch, 10) + ENCSP);
                String s = lookup.substring(ch, ch+1);
                out_SB.append(s + ENCSP);
                binEnc_SB.append(asBinStr(6, ch) + ENCSP);
                outBase64_SB.append(s);
            }
        }

        String rawF = rawF_SB.toString();
        String encDec = encDec_SB.toString();
        String encChars = encChars_SB.toString();
        String inpBin = inpBin_SB.toString();
        String binEnc = binEnc_SB.toString();

        assert(fixupLen<=3);
        assert(out_SB.length()>fixupLen);

        for (int j=0; j<fixupLen; ++j)
            out_SB.setCharAt(out_SB.length()-j-1, '=');
        String out = out_SB.toString();
        String outBase64 = outBase64_SB.toString();

        TableDiaplayBuilder bdlr = new TableDiaplayBuilder();

        String feedbackArgs  =
            bdlr.addRow("Your input" , HtmlUtils.htmlEscape(input_string))
                .addRow("cleaned" , HtmlUtils.htmlEscape(inp) )
                .addRow("inpBin" , inpBin )
                .addRow("binEnc" ,  binEnc)
                .addRow("encChars", encChars )
                .addRow("encDec", encDec )
                .addRow("out",  out )
                .build();

        return trackProgress(success()
                    .feedback("http-basics.encoding.base64")
                    .feedbackArgs(feedbackArgs)
                    .output("")
                    .outputArgs("")
                .build());
    }

    @RequestMapping(value="/base64", method = RequestMethod.GET)
    public
    @ResponseBody
    AttackResult handlerBase64Get(@RequestParam String input_string) throws IOException {

        String feedbackArgs = "display the input string in base64";
        return trackProgress(success()
                .feedback("http-basics.encoding.post.feedback")
                .feedbackArgs(feedbackArgs)
                .output("http-basics.lesson.success.output")
                .outputArgs("After trying a few strings, go to the next page" )
                .build());

    }


    class TableDiaplayBuilder {
        StringBuilder bldr;
        TableDiaplayBuilder() {
            bldr = new StringBuilder();
            bldr.append("<br>" + "<table border=1 style=font-family:monospace>");
        }

        TableDiaplayBuilder addRow (String key, String val) {
            bldr .append("<tr>"
                + "<th>" + key + "</th>"
                + "<td>" + val + "</td>"
                + "</tr>");
            return this;
        }

        String build() {
            bldr.append("/table>");
            return bldr.toString();
        }
    }


    static private String asBinStr(int width, int b) {
        String ot = "";
        for (int j=0; j<width; ++j) {
            if ((b & (1 << j)) != 0)
                ot = "1" + ot;
            else
                ot = "0" + ot;
        }
        ot += ENCSP;
        return ot;
    }

}
