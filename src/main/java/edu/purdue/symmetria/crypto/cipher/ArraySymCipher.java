package edu.purdue.symmetria.crypto.cipher;

import edu.purdue.symmetria.utils.MathUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * <pre>
 * Uses an array to hold the ids. ids can only be positive. cardinality can be positive or negative.
 *
 * Optimizations:
 *
 * 1. offset ids: save the difference of consecutive ids.
 *
 * Example:
 * ids = [3, 5, 6, 7, 8, 12]
 *
 * becomes:
 * offset = 3, ids = [0, 2, 1, 1, 1, 4]
 *
 * 2. Cardinalities stored in a map instead of an array. Only non-"1" cardinalities are stored.
 *
 * 3. ids are stored as an array of INTEGERS instead of LONGS.
 *
 * 4. TWO lists of ids, positive and negative
 *
 * 5. cancels outs ids in both pos and negative lists
 *
 * 6. Compresses lists
 *
 * </pre>
 */
public class ArraySymCipher extends SymCipher {

    // number of items in id arrays
    private int sizePos;
    private int sizeNeg;

    private long offsetPos;
    private long offsetNeg;

    // hold the ids
    private int[] idsPos;
    private int[] idsNeg;

    // for all cardinalities not in the map
    private long cardMultiplierPos;
    private long cardMultiplierNeg;

    // card multiplier does not apply for this map. The map holds the actual cardinality.
    // index of "ids" array--> cardinality
    private Map<Integer, Long> cardPos;
    private Map<Integer, Long> cardNeg;

    public ArraySymCipher(long value, long id) {
        setValue(value);
        sizePos = 1;
        offsetPos = id;
        idsPos = new int[1];
        cardMultiplierPos = 1;
    }

    /**
     * adds the ids of the other ciphertext to this ciphertext
     */
    private void addIds(ArraySymCipher other, boolean isPos) {
        int thisSize;
        long thisOffset;
        int[] thisIds;
        long thisCardMultiplier;
        Map<Integer, Long> thisCard;

        int otherSize;
        long otherOffset;
        int[] otherIds;
        long otherCardMultiplier;
        Map<Integer, Long> otherCard;

        // choose positive or negative items
        if (isPos) {
            thisSize = sizePos;
            thisOffset = offsetPos;
            thisIds = idsPos;
            thisCardMultiplier = cardMultiplierPos;
            thisCard = cardPos;

            otherSize = other.sizePos;
            otherOffset = other.offsetPos;
            otherIds = other.idsPos;
            otherCardMultiplier = other.cardMultiplierPos;
            otherCard = other.cardPos;
        } else {
            thisSize = sizeNeg;
            thisOffset = offsetNeg;
            thisIds = idsNeg;
            thisCardMultiplier = cardMultiplierNeg;
            thisCard = cardNeg;

            otherSize = other.sizeNeg;
            otherOffset = other.offsetNeg;
            otherIds = other.idsNeg;
            otherCardMultiplier = other.cardMultiplierNeg;
            otherCard = other.cardNeg;
        }

        if (otherSize == 0)
            return;

        int newSize;
        long newOffset = 0;
        int[] newIds;
        long newCardMultiplier;
        Map<Integer, Long> newCard;

        if (thisSize == 0) {
            newSize = otherSize;
            newOffset = otherOffset;
            newIds = otherIds;
            newCardMultiplier = otherCardMultiplier;
            newCard = otherCard;
        } else {
            // upper bound on new size since ids can cancel out, i.e., in case cardinality
            // sums up to 0.
            int upperSize = thisSize + otherSize;
            newIds = new int[upperSize];
            newCard = new HashMap<>();

            // keep the cardinality multiplier of the longest ciphertext
            newCardMultiplier = thisCardMultiplier;
            if (thisSize < otherSize)
                newCardMultiplier = otherCardMultiplier;

            int thisIndex = 0;
            int otherIndex = 0;
            int newIndex = 0;
            long currentOffset = 0;

            while (thisIndex < thisSize || otherIndex < otherSize) {

                long thisId = -1;
                long otherId = -1;
                if (thisIndex < thisSize)
                    thisId = thisOffset + thisIds[thisIndex];
                if (otherIndex < otherSize)
                    otherId = otherOffset + otherIds[otherIndex];

                if (otherIndex >= otherSize || (thisIndex < thisSize && thisId < otherId)) {
                    // set the id
                    newIds[newIndex] = (int) (thisId - currentOffset);
                    if (newIndex == 0) {
                        newOffset = newIds[newIndex];
                        newIds[newIndex] = 0;
                    }

                    // update offsets
                    thisOffset = thisId;
                    currentOffset = thisId;

                    // set the cardinality
                    long card = thisCardMultiplier;
                    if (thisCard != null && thisCard.containsKey(thisIndex))
                        card = thisCard.get(thisIndex);
                    if (card != newCardMultiplier)
                        newCard.put(newIndex, card);

                    // update indices
                    thisIndex++;
                    newIndex++;
                } else if (thisIndex >= thisSize || otherId < thisId) {
                    // set the id
                    newIds[newIndex] = (int) (otherId - currentOffset);
                    if (newIndex == 0) {
                        newOffset = newIds[newIndex];
                        newIds[newIndex] = 0;
                    }

                    // update offsets
                    otherOffset = otherId;
                    currentOffset = otherId;

                    // set the cardinality
                    long card = otherCardMultiplier;
                    if (otherCard != null && otherCard.containsKey(otherIndex))
                        card = otherCard.get(otherIndex);
                    if (card != newCardMultiplier)
                        newCard.put(newIndex, card);

                    // update indices
                    otherIndex++;
                    newIndex++;
                } else {
                    // set the id
                    newIds[newIndex] = (int) (thisId - currentOffset);
                    if (newIndex == 0) {
                        newOffset = newIds[newIndex];
                        newIds[newIndex] = 0;
                    }

                    // update offsets
                    thisOffset = thisId;
                    otherOffset = thisId;
                    currentOffset = thisId;

                    // set the cardinality
                    long card1 = thisCardMultiplier;
                    if (thisCard != null && thisCard.containsKey(thisIndex))
                        card1 = thisCard.get(thisIndex);

                    long card2 = otherCardMultiplier;
                    if (otherCard != null && otherCard.containsKey(otherIndex))
                        card2 = otherCard.get(otherIndex);

                    long card = card1 + card2;
                    if (card != newCardMultiplier)
                        newCard.put(newIndex, card);

                    // update indices
                    thisIndex++;
                    otherIndex++;
                    newIndex++;
                }
            }
            newSize = newIndex;
        }

        if (isPos) {
            sizePos = newSize;
            offsetPos = newOffset;
            idsPos = newIds;
            cardMultiplierPos = newCardMultiplier;
            cardPos = newCard;
        } else {
            sizeNeg = newSize;
            offsetNeg = newOffset;
            idsNeg = newIds;
            cardMultiplierNeg = newCardMultiplier;
            cardNeg = newCard;
        }
    }

    private void addIds(ArraySymCipher other) {
        addIds(other, true);
        addIds(other, false);
    }

    private void multiplyIds(long multiplier, long modulo) {
        if (multiplier == 0) {
            sizePos = 0;
            sizeNeg = 0;
            offsetPos = 0;
            offsetNeg = 0;
            idsPos = null;
            idsNeg = null;
            cardMultiplierPos = 1;
            cardMultiplierNeg = 1;
            cardPos = null;
            cardNeg = null;
            return;
        }

        // swap
        if (multiplier < 0) {
            multiplier = -multiplier;
            // swap sizes
            int size = sizePos;
            sizePos = sizeNeg;
            sizeNeg = size;

            // swap offsets
            long offset = offsetPos;
            offsetPos = offsetNeg;
            offsetNeg = offset;

            // swap ids
            int[] ids = idsPos;
            idsPos = idsNeg;
            idsNeg = ids;

            // swap cardMultiplier
            long cm = cardMultiplierPos;
            cardMultiplierPos = cardMultiplierNeg;
            cardMultiplierNeg = cm;

            // swap cardinalities
            Map<Integer, Long> card = cardPos;
            cardPos = cardNeg;
            cardNeg = card;
        }

        if (multiplier == 1)
            return;

        cardMultiplierPos = MathUtils.modMul(cardMultiplierPos, multiplier, modulo);
        if (cardPos != null)
            for (Map.Entry<Integer, Long> entry : cardPos.entrySet())
                cardPos.put(entry.getKey(), MathUtils.modMul(entry.getValue(), multiplier, modulo));

        cardMultiplierNeg = MathUtils.modMul(cardMultiplierNeg, multiplier, modulo);
        if (cardNeg != null)
            for (Map.Entry<Integer, Long> entry : cardNeg.entrySet())
                cardNeg.put(entry.getKey(), MathUtils.modMul(entry.getValue(), multiplier, modulo));
    }

    @Override
    public int getSize() {
        return this.sizePos + this.sizeNeg;
    }

    @Override
    public long[][] getIds() {
        int size = getSize();
        long[] ids = new long[size];
        long[] card = new long[size];

        long currentOffset = offsetPos;
        for (int i = 0; i < sizePos; i++) {
            long id = currentOffset + idsPos[i];
            currentOffset = id;
            ids[i] = id;

            long c = this.cardMultiplierPos;
            if (this.cardPos != null && this.cardPos.containsKey(i))
                c = this.cardPos.get(i);
            card[i] = c;
        }

        currentOffset = offsetNeg;
        for (int i = 0; i < sizeNeg; i++) {
            long id = currentOffset + idsNeg[i];
            currentOffset = id;
            ids[i + sizePos] = id;

            long c = this.cardMultiplierNeg;
            if (this.cardNeg != null && this.cardNeg.containsKey(i))
                c = this.cardNeg.get(i);
            card[i + sizePos] = -c;
        }

        return new long[][]{ids, card};
    }

    @Override
    public void add(SymCipher other, long modulo) {
        addValue(other.getValue(), modulo);
        addIds((ArraySymCipher) other);
    }

    @Override
    public void sub(SymCipher other, long modulo) {
        subValue(other.getValue(), modulo);
        ArraySymCipher o = (ArraySymCipher) other;
        o.multiplyIds(-1, modulo);
        addIds(o);
    }

    @Override
    public void multiply(long m, long modulo) {
        this.multiplyValue(m, modulo);
        this.multiplyIds(m, modulo);
    }

    @Override
    public void multiply(SymCipher other, long modulo) {
        this.multiplyValue(other.getValue(), modulo);
        this.addIds((ArraySymCipher) other);
    }

    @Override
    public void pow(long m, long modulo) {
        this.raiseValue(m, modulo);
        this.multiplyIds(m, modulo);
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "<\nvalue=" + this.getValue() +
                "\nPOS=\n\tsiz=" + sizePos +
                "\n\tofs=" + offsetPos +
                "\n\tids=" + Arrays.toString(idsPos) +
                "\n\tmult=" + cardMultiplierPos +
                "\n\tcard=" + cardPos +
                "\nNEG=\n\tsiz=" + sizeNeg +
                "\n\tofs=" + offsetNeg +
                "\n\tids=" + Arrays.toString(idsNeg) +
                "\n\tcml=" + cardMultiplierNeg +
                "\n\tcrd=" + cardNeg +
                ">";
    }

}