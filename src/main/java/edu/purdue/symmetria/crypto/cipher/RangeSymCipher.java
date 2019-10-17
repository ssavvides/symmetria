package edu.purdue.symmetria.crypto.cipher;

import edu.purdue.symmetria.utils.MathUtils;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


public class RangeSymCipher extends SymCipher {

    /**
     * The first id is stored as the `offset`. Every other id is stored in `ids` as the
     * difference of the id minus the previous id.
     */
    static class CardId {
        // the amount by which the ids array is extended if it cannot hold more more ids.
        private static final int EXTEND_BY = 5;

        // stores the first (smallest) id
        private long offset;

        // the last id
        private long lastId;

        // number of items in array
        private int size;

        // the total number of ids held
        private int total;

        // holds the id offsets excluding the first id.
        private int[] ids;

        // `ids` index to number of consecutive ids.
        private Map<Integer, Integer> ranges;

        public CardId(long offset) {
            this.size = 0;
            this.total = 1;
            this.offset = offset;
            this.lastId = offset;
            this.ids = null;
            this.ranges = null;
        }

        private int getRange(int index) {
            if (this.ranges == null)
                return 0;
            return this.ranges.getOrDefault(index, 0);
        }

        private void putRange(int index, int range) {
            if (this.ranges == null)
                this.ranges = new HashMap<>();
            this.ranges.put(index, range);
        }

        /**
         * Adds given id at position size of the array and adds its associated range if it's not zero.
         */
        private void addNext(long id, int range) {
            // if the ids array cannot hold more ids, increase its size.
            if (ids == null)
                this.ids = new int[EXTEND_BY];
            else if (this.ids.length <= size) {
                int[] newIds = new int[size + EXTEND_BY];
                System.arraycopy(this.ids, 0, newIds, 0, this.size);
                this.ids = newIds;
            }
            int index = size++;
            this.ids[index] = (int) (id - this.lastId);
            this.lastId = id;
            if (range > 0)
                putRange(index, range);
        }

        /**
         * Add `id` at the end of the ids array. Expects that `id >= this.lastId`.
         */
        private void addIdEnd(long id, int range) {
            if (id < this.lastId)
                throw new RuntimeException("attempted to add id `" + id + "` when last id was `" + this.lastId + "`");

            // check if given id is exactly 1 larger than the last its including range
            int thisRange = getRange(size - 1);
            long toMatch = this.lastId + thisRange + 1;
            if (id == toMatch) {
                // match: just increment the range
                putRange(size - 1, thisRange + range + 1);
                return;
            }

            // no match: add to array
            addNext(id, range);
        }

        /**
         * Adds at the end of the ids of this object. Expects that other ids are all larger
         * Expects: `other.offset >= this.lastId`.
         */
        private void addAfter(CardId other) {
            // extend array if needed. if `other.size` is zero then the given object contains only
            // a single id in offset, in which case we don't extend the array in case the new id
            // can be captured as a range.
            if (other.size > 0) {
                int newSize = this.size + other.size + 1;
                if (ids == null)
                    this.ids = new int[newSize + EXTEND_BY];
                else if (this.ids.length <= newSize) {
                    int[] newIds = new int[newSize + EXTEND_BY];
                    System.arraycopy(this.ids, 0, newIds, 0, this.size);
                    this.ids = newIds;
                }
            }

            // add other offset
            addIdEnd(other.offset, 0);

            // add other ids
            long realId = other.offset;
            for (int index = 0; index < other.size; index++) {
                int range = other.getRange(index);
                realId += other.ids[index];
                addIdEnd(realId, range);
            }
        }

        /**
         * TODO: merge without creating new array
         */
        public void add(CardId other) {
            if (other == null)
                return;

            this.total += other.total;

            // other ids are all >= this ids.
            if (other.offset >= this.lastId) {
                addAfter(other);
                return;
            }

            // size of this and other ids plus 1 offset.
            int newSize = this.size + other.size + 1;
            int[] thisIds = this.ids;
            this.ids = null;
            if (newSize > 1)
                this.ids = new int[newSize];

            Map<Integer, Integer> thisRanges = this.ranges;
            this.ranges = null;

            int thisSize = this.size;
            this.size = 0;

            int thisIndex = -1;
            int otherIndex = -1;
            long thisOffset = this.offset;
            long otherOffset = other.offset;

            // set new offset to be the smallest of this and other offset
            if (thisOffset < otherOffset) {
                this.offset = thisOffset;
                int range = (thisRanges == null) ? 0 : thisRanges.getOrDefault(thisIndex, 0);
                if (range != 0)
                    this.putRange(-1, range);
                this.lastId = this.offset;
                thisIndex = 0;
            } else {
                this.offset = otherOffset;
                this.lastId = this.offset;
                otherIndex = 0;
            }

            while (thisIndex < thisSize || otherIndex < other.size) {
                long thisId = (thisIndex == -1 || thisIndex >= thisSize) ? thisOffset : thisOffset + thisIds[thisIndex];
                long otherId = (otherIndex == -1 || otherIndex >= other.size) ? otherOffset : otherOffset + other.ids[otherIndex];

                if (otherIndex >= other.size || thisId < otherId) {
                    int range = (thisRanges == null) ? 0 : thisRanges.getOrDefault(thisIndex, 0);
                    addIdEnd(thisId, range);
                    thisOffset = thisId;
                    thisIndex++;
                } else {
                    int range = other.getRange(otherIndex);
                    addIdEnd(otherId, range);
                    otherOffset = otherId;
                    otherIndex++;
                }
            }
        }

        private int toArray(int index, long[] array, long id, int idIndex) {
            array[index++] = id;
            int range = getRange(idIndex);
            for (int i = 0; i < range; i++) {
                array[index++] = id + i + 1;
            }
            return index;
        }

        public long[] toArray() {
            long[] array = new long[this.total];
            int index = 0;

            long id = this.offset;
            index = toArray(index, array, id, -1);

            if (this.ids != null) {
                for (int i = 0; i < this.size; i++) {
                    id += this.ids[i];
                    index = toArray(index, array, id, i);
                }
            }

            return array;
        }

        public int byteSize() {
            int bytes = Long.BYTES + Long.BYTES + Integer.BYTES + Integer.BYTES;
            bytes += size * Integer.BYTES;
            if (ranges != null)
                bytes += ranges.size() * Integer.BYTES * 2;
            return bytes;
        }

        @Override
        public String toString() {
            return "[size=" + this.size + " offset=" + this.offset + " ids=" + Arrays.toString(this.ids) + " ranges=" + this.ranges + "]";
        }
    }

    // a map of cardinalities to ids
    private Map<Long, CardId> ids;

    // total number of ids stored
    private int size;

    public RangeSymCipher(long value, long id) {
        setValue(value);
        CardId cardId = new CardId(id);
        this.ids = new HashMap<>();
        this.ids.put(1L, cardId);
        this.size = 1;
    }

    public RangeSymCipher(ByteBuffer bb) {
        throw new RuntimeException("Unimplemented");
    }

    void addIds(Long card, CardId cardId) {
        if (!this.ids.containsKey(card)) {
            this.ids.put(card, cardId);
        } else
            this.ids.get(card).add(cardId);
    }

    void addIds(RangeSymCipher other) {
        if (other.ids == null)
            return;
        if (this.ids == null) {
            this.ids = other.ids;
            this.size = other.size;
            return;
        }
        this.size += other.size;
        for (Map.Entry<Long, CardId> entry : other.ids.entrySet())
            addIds(entry.getKey(), entry.getValue());
    }

    void multiplyIds(long multiplier, long modulo) {
        if (multiplier == 0) {
            this.ids = null;
            return;
        }
        if (multiplier == 1 || ids == null)
            return;

        Map<Long, CardId> newIds = new HashMap<>();
        for (Long card : ids.keySet())
            newIds.put(MathUtils.modMul(card, multiplier, modulo), ids.get(card));
        ids = newIds;
    }

    @Override
    public int getSize() {
        return this.size;
    }

    @Override
    public long[][] getIds() {
        long[][] ids = new long[2][this.size];
        int index = 0;
        if (this.ids != null)
            for (Long card : this.ids.keySet()) {
                CardId cid = this.ids.get(card);
                long[] array = cid.toArray();
                for (long id : array) {
                    ids[0][index] = id;
                    ids[1][index] = card;
                    index++;
                }

            }
        return ids;
    }

    @Override
    public void add(SymCipher other, long modulo) {
        addValue(other.getValue(), modulo);
        addIds((RangeSymCipher) other);
    }

    @Override
    public void sub(SymCipher other, long modulo) {
        subValue(other.getValue(), modulo);
        RangeSymCipher o = (RangeSymCipher) other;
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
        this.addIds((RangeSymCipher) other);
    }

    @Override
    public void pow(long m, long modulo) {
        this.raiseValue(m, modulo);
        this.multiplyIds(m, modulo);
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "<\nvalue=" + this.getValue() + "\n" +
                this.ids.toString() + "\n>";
    }

    public int byteSize() {
        int bytes = Integer.BYTES;
        if (this.ids != null)
            for (Long card : this.ids.keySet()) {
                bytes += Long.BYTES;
                bytes += this.ids.get(card).byteSize();
            }
        return bytes;
    }

    public static void main(String[] args) {
        RangeSymCipher r1 = new RangeSymCipher(1, 25);
        RangeSymCipher r2 = new RangeSymCipher(100, 24);
        RangeSymCipher r3 = new RangeSymCipher(1000, 124);
        RangeSymCipher r4 = new RangeSymCipher(1000, 123);
        r1.add(r2, Long.MAX_VALUE);
        r1.add(r3, Long.MAX_VALUE);
        r1.add(r4, Long.MAX_VALUE);
        System.out.println(r1);
    }

}