const PositiveInteger = 0;
const NegativeInteger = 1;
const ByteString = 2;
const TextString = 3;
const Array = 4;
const Map = 5;

export class BinaryReader {
    constructor(buffer) {
        if (!(buffer instanceof ArrayBuffer)) throw new TypeError();
        this.view = new DataView(buffer);
        this.offset = 0;
    }
    get readerOffset() { return this.offset; }
    get buffer() { return this.view.buffer; }
    get byteOffset() { return this.view.byteOffset; }
    get byteLength() { return this.view.byteLength; }
    readUInt8() {
        const value = this.view.getUint8(this.offset);
        this.offset += 1;
        return value;
    }
    readUInt16() {
        const value = this.view.getUint16(this.offset);
        this.offset += 2;
        return value;
    }
    readUInt32() {
        const value = this.view.getUint32(this.offset);
        this.offset += 4;
        return value;
    }
    readUInt64() {
        const value = this.view.getBigUint64(this.offset);
        this.offset += 8;
        return Number(value);
    }
    readBytes(length) {
        const value = this.view.buffer.slice(this.offset, this.offset + length);
        this.offset += length;
        return value;
    }
}

class Header {
    major = 0;
    information = 0;
    length = 0;
    constructor(h) {
        this.major = h >> 5 & 0x7;
        this.information = h & 0x1f;
    }
}

export class CborSimpleDecoder {
    static readHeader(reader) {
        if (!(reader instanceof BinaryReader)) throw new TypeError();
        const h = reader.readUInt8();
        const header = new Header(h);
        if (header.information >= 0 && header.information <= 23) {
            header.length = header.information;
        } else if (header.information == 24) {
            header.length = reader.readUInt8();
        } else if (header.information == 25) {
            header.length = reader.readUInt16();
        } else if (header.information == 26) {
            header.length = reader.readUInt32();
        } else if (header.information == 27) {
            header.length = reader.readUInt64();
        } else {
            throw new Error(`not implemented: major=${header.major} information=${header.information}`);
        }
        return header;
    }
    static readObject(reader) {
        if (!(reader instanceof BinaryReader)) throw new TypeError();
        const header = CborSimpleDecoder.readHeader(reader);
        switch (header.major) {
            case PositiveInteger:
                return header.length;
            case NegativeInteger:
                return -1 - header.length;
            case ByteString:
                return reader.readBytes(header.length);
            case TextString:
                const utf = new TextDecoder("utf-8");
                return utf.decode(reader.readBytes(header.length));
            case Array:
                const array = [];
                for (let i = 0; i < header.length; i++) {
                    const obj = CborSimpleDecoder.readObject(reader);
                    array.push(obj);
                }
                return array;
            case Map:
                const map = {};
                for (let i = 0; i < header.length; i++) {
                    const key = CborSimpleDecoder.readObject(reader);
                    const value = CborSimpleDecoder.readObject(reader);
                    map[key] = value;
                }
                return map;
            default:
                throw new Error(`not implemented: major=${header.major} information=${header.information}`);
        }
    }
}
