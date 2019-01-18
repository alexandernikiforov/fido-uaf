/*
 *      FIDO UAF 1.1 Assertions Generator and Parser
 *      Copyright (C) 2019  Alexander Nikiforov
 *
 *      This program is free software: you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation, either version 3 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package ch.alni.fido.uaf.authnr.tlv;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Composite tag that includes other tags (composite or single).
 */
public class CompositeTag extends TlvStruct {
    private final List<TlvStruct> tags = new ArrayList<>();

    public CompositeTag(int position, int tag, int length, List<TlvStruct> tags) {
        super(position, tag, length);

        if (0 == (tag & 0x1000)) {
            throw new IllegalArgumentException("provided tag is not a composite: " + tag);
        }

        this.tags.addAll(tags);
    }

    public List<TlvStruct> getTags() {
        return Collections.unmodifiableList(tags);
    }
}
