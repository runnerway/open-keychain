package org.sufficientlysecure.keychain.ui.util;

import android.content.Context;
import android.text.Spannable;
import android.text.style.ForegroundColorSpan;

import org.sufficientlysecure.keychain.R;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Highlighter {
    private Context mContext;
    private String mQuery;

    public Highlighter(Context context, String query) {
        mContext = context;
        mQuery = query;
    }

    public Spannable highlight(String text) {
        if (text == null)
            return null;

        Spannable highlight = Spannable.Factory.getInstance().newSpannable(text);

        if (mQuery == null) {
            return highlight;
        }

        String queryPattern = buildPatternFromQuery(mQuery);
        Pattern pattern = Pattern.compile("(" + queryPattern + ")", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(text);

        int colorEmphasis = FormattingUtils.getColorFromAttr(mContext, R.attr.colorEmphasis);

        while (matcher.find()) {
            highlight.setSpan(new ForegroundColorSpan(colorEmphasis),
                    matcher.start(), matcher.end(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        return highlight;
    }

    private static String buildPatternFromQuery(String mQuery) {
        String chunks[] = mQuery.split(" *, *");
        boolean firstChunk = true;
        StringBuilder patternPiece = new StringBuilder();
        for (int i = 0; i < chunks.length; ++i) {
            patternPiece.append(Pattern.quote(chunks[i]));
            if (firstChunk) {
                firstChunk = false;
                continue;
            }
            patternPiece.append('|');
        }
        return patternPiece.toString();
    }
}
