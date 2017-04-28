import json
from collections import defaultdict

def pkt_to_json(pkt):
    results = defaultdict(dict)
    results['_time_'] = pkt['time']

    raw_pkt = pkt['raw_pkt']

    try:
        for index in range(50):
            layer = raw_pkt[index]
            layer_len = len(layer)

            # Get layer name
            layer_tmp_name = str(layer.aliastypes[0])
            layer_start_pos = layer_tmp_name.rfind(".") + 1
            layer_name = layer_tmp_name[layer_start_pos:-2].lower()

            # Get the layer info
            tmp_t = {}
            for x, y in layer.default_fields.items():
                if y and not isinstance(y, (str, int, long, float, list, dict)):
                    tmp_t[x].update(pkt_to_json(y))
                else:
                    tmp_t[x] = y
            results[layer_name] = tmp_t

            try:
                tmp_t = {}
                for x, y in layer.fields.items():
                    if y and not isinstance(y, (str, int, long, float, list, dict)):
                        tmp_t[x].update(pkt_to_json(y))
                    elif x == 'load':
                        continue    # not support raw load now.
                    else:
                        tmp_t[x] = y
                results[layer_name] = tmp_t
            except KeyError:
              # No custom fields
                pass
            results[layer_name]['_len_'] = layer_len
            results[layer_name]['_idx_'] = index
    except IndexError:
        # Package finish -> do nothing
        pass

    return json.dumps(results, ensure_ascii=False)

def PacketsToJson(pkts):
    json_str = '['
    pkts_len = len(pkts)
    for i in xrange(pkts_len):
        json_str += pkt_to_json(pkts[i])
        if i != pkts_len - 1:
            json_str += ','
    json_str += ']'
    return json_str







