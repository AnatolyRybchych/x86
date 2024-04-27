#!/bin/python3

SOURCE: str = 'http://ref.x86asm.net/coder32.html'

def parse_html(html: str):
    from html.parser import HTMLParser

    class Parser(HTMLParser):
        def __init__(self, *, convert_charrefs: bool = True) -> None:
            super().__init__(convert_charrefs=convert_charrefs)

            self.dom = {}
            self.cur = [self.dom]

        def handle_starttag(self, tag: str, attrs):
            def append(list: list, item) -> list:
                if list:
                    list.append(item)
                    return list
                else:
                    return [item]

            attr_objs = {}
            for k, v in attrs:
                attr_objs[k] = append(attr_objs.get(k), v)

            element = {
                '.tag': tag,
                '.attr': attr_objs,
                '.data': None
            }

            self.cur[-1][tag] = append(self.cur[-1].get(tag), element)
            self.cur.append(element)

        def handle_endtag(self, tag: str):
            while len(self.cur) != 0 and self.cur[-1]['.tag'] != tag:
                self.cur.pop()
            
            assert len(self.cur) != 0
            self.cur.pop()

        def handle_data(self, data):
            self.cur[-1]['.data'] = data
        
    parser = Parser()
    parser.feed(html)
    return parser.dom

def inner_text(html: dict) -> list:
    result = []
    for k, inner in html.items():
        if k.startswith('.'):
            continue

        for v in inner:
            result += inner_text(v)

    return result + ([html['.data']] if '.data' in html and html['.data'] else [])

def parse_table(table: dict) -> list[dict]:
    thead = table['thead'][0]['tr'][0]
    cols = []
    for th in thead['th']:
        cols.append(th['.attr']['title'][0])

    entries = []
    for tbody in table['tbody']:
        entry = {}
        i = 0
        for td in tbody['tr'][0]['td']:
            entry[cols[i]] = ' '.join(inner_text(td)) or None
            if 'colspan' in td['.attr']:
                i += int(td['.attr']['colspan'][0])
            else:
                i += 1

        entries.append(entry)

    return entries

def del_nones(obj):
    if type(obj) is dict:
        return {k: del_nones(v) for k, v in obj.items() if v != None}
    elif type(obj) is list:
        return [del_nones(v) for v in obj if v != None]
    else:
        return obj

def parse_instructions():
    import requests

    dom = parse_html(requests.get(SOURCE).text)
    tables = dom['html'][0]['body'][0]['table']
    tab1 = parse_table(tables[0])
    tab2 = parse_table(tables[1])
    return del_nones(tab1 + tab2)

if __name__ == '__main__':
    import json
    import os
    import sys

    dir = os.path.dirname(os.path.realpath(sys.argv[0]))
    print(json.dumps(parse_instructions(), indent=4))
