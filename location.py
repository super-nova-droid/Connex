import os
import math
import googlemaps
from flask import current_app

def get_google_maps_client():
    """Initialize Google Maps client with API key"""
    api_key = os.environ.get('GOOGLE_MAPS_API_KEY')
    if not api_key:
        print("WARNING: GOOGLE_MAPS_API_KEY not found in environment variables")
        return None
    try:
        return googlemaps.Client(key=api_key)
    except Exception as e:
        print(f"WARNING: Failed to initialize Google Maps client: {e}")
        return None

def get_community_centers():
    """Return list of community centers with their coordinates"""
    return [
        {
            'location_id': 1,
            'location_name': 'ACE The Place Community Center',
            'full_address': '120 Woodlands Avenue 1 Singapore 739069',
            'lat': 1.427493,
            'lng': 103.792241
        },
        {
            'location_id': 2,
            'location_name': 'Aljunied Community Center',
            'full_address': '110 #1048 Hougang Avenue 1 Singapore 530110',
            'lat': 1.354658,
            'lng': 103.889546
        },
        {
            'location_id': 3,
            'location_name': 'Anchorvale Community Center',
            'full_address': '59 Anchorvale Road Singapore 544965',
            'lat': 1.397128,
            'lng': 103.886666
        },
        {
            'location_id': 4,
            'location_name': 'Ang Mo Kio Community Center',
            'full_address': '795 Ang Mo Kio Avenue 1 Singapore 569976',
            'lat': 1.366833,
            'lng': 103.840668
        },
        {
            'location_id': 5,
            'location_name': 'Ayer Rajah Community Center',
            'full_address': '150 Pandan Gardens Singapore 609335',
            'lat': 1.320799,
            'lng': 103.747540
        },
        {
            'location_id': 6,
            'location_name': 'Bedok Community Center',
            'full_address': '850 New Upper Changi Road Singapore 467352',
            'lat': 1.324247,
            'lng': 103.936048
        },
        {
            'location_id': 7,
            'location_name': 'Bidadari Community Center',
            'full_address': '11 Bidadari Park Drive Singapore 367803',
            'lat': 1.338731,
            'lng': 103.871670
        },
        {
            'location_id': 8,
            'location_name': 'Bishan Community Center',
            'full_address': '51 Bishan Street 13 Singapore 579799',
            'lat': 1.349512,
            'lng': 103.850509
        },
        {
            'location_id': 9,
            'location_name': 'Boon Lay Community Center',
            'full_address': '10 Boon Lay Place Singapore 649882',
            'lat': 1.348323,
            'lng': 103.711380
        },
        {
            'location_id': 10,
            'location_name': 'Braddell Heights Community Center',
            'full_address': '50 Serangoon Avenue 2 Singapore 556129',
            'lat': 1.351612,
            'lng': 103.870368
        },
        {
            'location_id': 11,
            'location_name': 'Buangkok Community Center',
            'full_address': '70 #25 Compassvale Bow Singapore 544692',
            'lat': 1.383435,
            'lng': 103.892191
        },
        {
            'location_id': 12,
            'location_name': 'Bukit Batok Community Center',
            'full_address': '21 Bukit Batok Central Singapore 659959',
            'lat': 1.350191,
            'lng': 103.747514
        },
        {
            'location_id': 13,
            'location_name': 'Bukit Batok East Community Center',
            'full_address': '23 Bukit Batok East Avenue 4 Singapore 659841',
            'lat': 1.348987,
            'lng': 103.758196
        },
        {
            'location_id': 14,
            'location_name': 'Bukit Merah Community Center',
            'full_address': '4000 Jalan Bukit Merah Singapore 159465',
            'lat': 1.285254,
            'lng': 103.815829
        },
        {
            'location_id': 15,
            'location_name': 'Bukit Panjang Community Center',
            'full_address': '8 Pending Road Singapore 678295',
            'lat': 1.376451,
            'lng': 103.770559
        },
        {
            'location_id': 16,
            'location_name': 'Bukit Timah Community Center',
            'full_address': '20 Toh Yi Drive Singapore 596569',
            'lat': 1.340501,
            'lng': 103.771610
        },
        {
            'location_id': 17,
            'location_name': 'Buona Vista Community Center',
            'full_address': '36 #1 Holland Drive Singapore 270036',
            'lat': 1.309259,
            'lng': 103.792619
        },
        {
            'location_id': 18,
            'location_name': 'Cairnhill Community Center',
            'full_address': '1 Anthony Road Singapore 229944',
            'lat': 1.310434,
            'lng': 103.838865
        },
        {
            'location_id': 19,
            'location_name': 'Canberra Community Center',
            'full_address': '2 Sembawang Crescent Singapore 757632',
            'lat': 1.445044,
            'lng': 103.819474
        },
        {
            'location_id': 20,
            'location_name': 'Changi Simei Community Center',
            'full_address': '10 Simei Street 2 Singapore 529915',
            'lat': 1.344936,
            'lng': 103.955111
        },
        {
            'location_id': 21,
            'location_name': 'Cheng San Community Center',
            'full_address': '6 Ang Mo Kio Street 53 Singapore 569205',
            'lat': 1.371780,
            'lng': 103.849570
        },
        {
            'location_id': 22,
            'location_name': 'Chong Pang Community Center',
            'full_address': '21 Yishun Ring Road Singapore 768677',
            'lat': 1.430832,
            'lng': 103.829235
        },
        {
            'location_id': 23,
            'location_name': 'Chua Chu Kang Community Center',
            'full_address': '35 Teck Whye Avenue Singapore 688892',
            'lat': 1.381155,
            'lng': 103.751904
        },
        {
            'location_id': 24,
            'location_name': 'Ci Yuan Community Center',
            'full_address': '51 Hougang Avenue 9 Singapore 538776',
            'lat': 1.375149,
            'lng': 103.882894
        },
        {
            'location_id': 25,
            'location_name': 'Clementi Community Center',
            'full_address': '220 Clementi Avenue 4 Singapore 129880',
            'lat': 1.318815,
            'lng': 103.768154
        },
        {
            'location_id': 26,
            'location_name': 'Dover Community Center',
            'full_address': '1 #300 Dover Road Singapore 130001',
            'lat': 1.302530,
            'lng': 103.783272
        },
        {
            'location_id': 27,
            'location_name': 'Eunos Community Center',
            'full_address': '180 Bedok Reservoir Road Singapore 479220',
            'lat': 1.332553,
            'lng': 103.915144
        },
        {
            'location_id': 28,
            'location_name': 'Fengshan Community Center',
            'full_address': '187B Bedok North Street 4 Singapore 462187',
            'lat': 1.330499,
            'lng': 103.939996
        },
        {
            'location_id': 29,
            'location_name': 'Fengshan Community Center',
            'full_address': '20 Bedok North Street 2 Singapore 469644',
            'lat': 1.330708,
            'lng': 103.936614
        },
        {
            'location_id': 30,
            'location_name': 'Fernvale Community Center',
            'full_address': '21 Sengkang West Avenue Singapore 797650',
            'lat': 1.391726,
            'lng': 103.877000
        },
        {
            'location_id': 31,
            'location_name': 'Fuchun Community Center',
            'full_address': '1 Woodlands Street 31 Singapore 738581',
            'lat': 1.429530,
            'lng': 103.774812
        },
        {
            'location_id': 32,
            'location_name': 'Gek Poh Ville Community Center',
            'full_address': '1 Jurong West Street 74 Singapore 649149',
            'lat': 1.348690,
            'lng': 103.698726
        },
        {
            'location_id': 33,
            'location_name': 'Geylang Serai Community Center',
            'full_address': '1 Engku Aman Turn Singapore 408528',
            'lat': 1.316450,
            'lng': 103.896597
        },
        {
            'location_id': 34,
            'location_name': 'Geylang West Community Center',
            'full_address': '1205 Upper Boon Keng Road Singapore 387311',
            'lat': 1.315691,
            'lng': 103.872388
        },
        {
            'location_id': 35,
            'location_name': 'Henderson Community Center',
            'full_address': '500 Bukit Merah View Singapore 159682',
            'lat': 1.286010,
            'lng': 103.823315
        },
        {
            'location_id': 36,
            'location_name': 'Hillview Community Center',
            'full_address': '1 Hillview Rise Singapore 667970',
            'lat': 1.361967,
            'lng': 103.764266
        },
        {
            'location_id': 37,
            'location_name': 'Hong Kah North Community Center',
            'full_address': '30 Bukit Batok Street 31 Singapore 659440',
            'lat': 1.359059,
            'lng': 103.749457
        },
        {
            'location_id': 38,
            'location_name': 'Hougang Community Center',
            'full_address': '35 Hougang Avenue 3 Singapore 538840',
            'lat': 1.364757,
            'lng': 103.892622
        },
        {
            'location_id': 39,
            'location_name': 'Hwi Yoh Community Center',
            'full_address': '535 #179 Serangoon North Avenue 4 Singapore 550535',
            'lat': 1.373600,
            'lng': 103.873891
        },
        {
            'location_id': 40,
            'location_name': 'Jalan Besar Community Center',
            'full_address': '69 Jellicoe Road Singapore 208737',
            'lat': 1.308004,
            'lng': 103.861787
        },
        {
            'location_id': 41,
            'location_name': 'Joo Chiat Community Center',
            'full_address': '405 Joo Chiat Road Singapore 427633',
            'lat': 1.307457,
            'lng': 103.904169
        },
        {
            'location_id': 42,
            'location_name': 'Jurong Green Community Center',
            'full_address': '6 Jurong West Avenue 1 Singapore 649520',
            'lat': 1.350556,
            'lng': 103.725342
        },
        {
            'location_id': 43,
            'location_name': 'Jurong Spring Community Center',
            'full_address': '8 Jurong West Street 52 Singapore 649296',
            'lat': 1.348330,
            'lng': 103.718156
        },
        {
            'location_id': 44,
            'location_name': 'Kaki Bukit Community Center',
            'full_address': '670 Bedok North Street 3 Singapore 469627',
            'lat': 1.333382,
            'lng': 103.926846
        },
        {
            'location_id': 45,
            'location_name': 'Kallang Community Center',
            'full_address': '45 Boon Keng Road Singapore 339771',
            'lat': 1.317803,
            'lng': 103.862373
        },
        {
            'location_id': 46,
            'location_name': 'Kampong Chai Chee Community Center/Heartbeat @Bedok',
            'full_address': '11 Bedok North Street 1 Singapore 469662',
            'lat': 1.326985,
            'lng': 103.931621
        },
        {
            'location_id': 47,
            'location_name': 'Kampong Glam Community Center',
            'full_address': '385 Beach Road Singapore 199581',
            'lat': 1.302795,
            'lng': 103.863598
        },
        {
            'location_id': 48,
            'location_name': 'Kampong Kembangan Community Center',
            'full_address': '5 Lengkong Tiga Singapore 417408',
            'lat': 1.323155,
            'lng': 103.912699
        },
        {
            'location_id': 49,
            'location_name': 'Kampong Ubi Community Center',
            'full_address': '10 Jalan Ubi Singapore 409075',
            'lat': 1.317846,
            'lng': 103.900750
        },
        {
            'location_id': 50,
            'location_name': 'Katong Community Center',
            'full_address': '51 Kampong Arang Road Singapore 438178',
            'lat': 1.300591,
            'lng': 103.884749
        },
        {
            'location_id': 51,
            'location_name': 'Keat Hong Community Center',
            'full_address': '2 #1 Choa Chu Kang Loop Singapore 689687',
            'lat': 1.384065,
            'lng': 103.744924
        },
        {
            'location_id': 52,
            'location_name': 'Kebun Baru Community Center',
            'full_address': '216 Ang Mo Kio Avenue 4 Singapore 569897',
            'lat': 1.373007,
            'lng': 103.837612
        },
        {
            'location_id': 53,
            'location_name': 'Kim Seng Community Center',
            'full_address': '570 Havelock Road Singapore 169640',
            'lat': 1.289683,
            'lng': 103.830706
        },
        {
            'location_id': 54,
            'location_name': 'Kolam Ayer Community Center',
            'full_address': '1 Geylang Bahru Lane Singapore 339631',
            'lat': 1.324154,
            'lng': 103.869693
        },
        {
            'location_id': 55,
            'location_name': 'Kreta Ayer Community Center',
            'full_address': '28A Kreta Ayer Road Singapore 088995',
            'lat': 1.281193,
            'lng': 103.843013
        },
        {
            'location_id': 56,
            'location_name': 'Leng Kee Community Center',
            'full_address': '400 Lengkok Bahru Singapore 159049',
            'lat': 1.289787,
            'lng': 103.814448
        },
        {
            'location_id': 57,
            'location_name': 'Limbang CO c/o Yew Tee Community Center',
            'full_address': '20 #10 Choa Chu Kang Street 52 Singapore 689286',
            'lat': 1.394918,
            'lng': 103.744728
        },
        {
            'location_id': 58,
            'location_name': 'MacPherson Community Center',
            'full_address': '400 Paya Lebar Way Singapore 379131',
            'lat': 1.323537,
            'lng': 103.884481
        },
        {
            'location_id': 59,
            'location_name': 'Marine Parade Community Center',
            'full_address': '278 Marine Parade Road Singapore 449282',
            'lat': 1.304829,
            'lng': 103.909545
        },
        {
            'location_id': 60,
            'location_name': 'Marsiling Community Center',
            'full_address': '100 Admiralty Road Singapore 739980',
            'lat': 1.440657,
            'lng': 103.773615
        },
        {
            'location_id': 61,
            'location_name': 'Marymount Community Center',
            'full_address': '191 Sin Ming Avenue Singapore 575738',
            'lat': 1.362138,
            'lng': 103.841286
        },
        {
            'location_id': 62,
            'location_name': 'Mountbatten Community Center',
            'full_address': '14 #45 Kampong Arang Road Singapore 431014',
            'lat': 1.300178,
            'lng': 103.884043
        },
        {
            'location_id': 63,
            'location_name': 'Mountbatten Community Center',
            'full_address': '87 Jalan Satu Singapore 390087',
            'lat': 1.309235,
            'lng': 103.886827
        },
        {
            'location_id': 64,
            'location_name': 'Nanyang Community Center',
            'full_address': '60 Jurong West Street 91 Singapore 649040',
            'lat': 1.342364,
            'lng': 103.692320
        },
        {
            'location_id': 65,
            'location_name': 'Nee Soon Central Community Center',
            'full_address': '1 #201 Northpoint Drive Singapore 768019',
            'lat': 1.428036,
            'lng': 103.836092
        },
        {
            'location_id': 66,
            'location_name': 'Nee Soon East Community Center',
            'full_address': '1 Yishun Avenue 9 Singapore 768893',
            'lat': 1.431021,
            'lng': 103.838488
        },
        {
            'location_id': 67,
            'location_name': 'Nee Soon South Community Center',
            'full_address': '30 Yishun Street 81 Singapore 768455',
            'lat': 1.415175,
            'lng': 103.834693
        },
        {
            'location_id': 68,
            'location_name': 'One Punggol Community Center',
            'full_address': '1 #4 Punggol Drive Singapore 828629',
            'lat': 1.408618,
            'lng': 103.905088
        },
        {
            'location_id': 69,
            'location_name': 'Pasir Ris East Community Center',
            'full_address': '1 Pasir Ris Drive 4 Singapore 519457',
            'lat': 1.368587,
            'lng': 103.959198
        },
        {
            'location_id': 70,
            'location_name': 'Pasir Ris Elias Community Center',
            'full_address': '93 Pasir Ris Drive 3 Singapore 519498',
            'lat': 1.378429,
            'lng': 103.942476
        },
        {
            'location_id': 71,
            'location_name': 'Paya Lebar Kovan Community Center',
            'full_address': '207 Hougang Street 21 Singapore 530207',
            'lat': 1.357799,
            'lng': 103.886092
        },
        {
            'location_id': 72,
            'location_name': 'Pek Kio Community Center',
            'full_address': '21 Gloucester Road Singapore 219458',
            'lat': 1.313059,
            'lng': 103.851374
        },
        {
            'location_id': 73,
            'location_name': 'Potong Pasir Community Center',
            'full_address': '6 Potong Pasir Avenue 2 Singapore 358361',
            'lat': 1.332536,
            'lng': 103.867037
        },
        {
            'location_id': 74,
            'location_name': 'Punggol 21 Community Center',
            'full_address': '80 Punggol Field Singapore 828815',
            'lat': 1.393606,
            'lng': 103.913464
        },
        {
            'location_id': 75,
            'location_name': 'Punggol Community Center',
            'full_address': '3 Hougang Avenue 6 Singapore 538808',
            'lat': 1.374379,
            'lng': 103.891815
        },
        {
            'location_id': 76,
            'location_name': 'Punggol Park Community Center',
            'full_address': '458 #405 Hougang Avenue 10 Singapore 530458',
            'lat': 1.377734,
            'lng': 103.896253
        },
        {
            'location_id': 77,
            'location_name': 'Punggol Vista Community Center',
            'full_address': '602 #2 Punggol Central Singapore 820602',
            'lat': 1.403284,
            'lng': 103.907289
        },
        {
            'location_id': 78,
            'location_name': 'Punggol West Community Center',
            'full_address': '259C #47 Punggol Field Singapore 823259',
            'lat': 1.404516,
            'lng': 103.895665
        },
        {
            'location_id': 79,
            'location_name': 'Queenstown Community Center',
            'full_address': '365 Commonwealth Avenue Singapore 149732',
            'lat': 1.299150,
            'lng': 103.801305
        },
        {
            'location_id': 80,
            'location_name': 'Radin Mas Community Center',
            'full_address': '51 Telok Blangah Crescent Singapore 098917',
            'lat': 1.275931,
            'lng': 103.819753
        },
        {
            'location_id': 81,
            'location_name': 'Rivervale Community Center',
            'full_address': '2 Rivervale Close Singapore 544583',
            'lat': 1.385153,
            'lng': 103.902320
        },
        {
            'location_id': 82,
            'location_name': 'Sembawang Community Center',
            'full_address': '2125 Sembawang Road Singapore 758528',
            'lat': 1.451682,
            'lng': 103.828783
        },
        {
            'location_id': 83,
            'location_name': 'Sengkang Community Center',
            'full_address': '2 #1 Sengkang Square Singapore 545025',
            'lat': 1.392786,
            'lng': 103.893906
        },
        {
            'location_id': 84,
            'location_name': 'Senja-Cashew Community Center',
            'full_address': '101 Bukit Panjang Road Singapore 679910',
            'lat': 1.381587,
            'lng': 103.764660
        },
        {
            'location_id': 85,
            'location_name': 'Siglap Community Center',
            'full_address': '300 Bedok South Avenue 3 Singapore 469299',
            'lat': 1.321632,
            'lng': 103.943337
        },
        {
            'location_id': 86,
            'location_name': 'Siglap Community Center',
            'full_address': '151 Bedok South Road Singapore 460151',
            'lat': 1.317292,
            'lng': 103.946742
        },
        {
            'location_id': 87,
            'location_name': 'Siglap South Community Center',
            'full_address': '6 Palm Road Singapore 456441',
            'lat': 1.313159,
            'lng': 103.930623
        },
        {
            'location_id': 88,
            'location_name': 'Taman Jurong Community Center',
            'full_address': '1 Yung Sheng Road Singapore 618495',
            'lat': 1.335307,
            'lng': 103.721626
        },
        {
            'location_id': 89,
            'location_name': 'Tampines Central Community Center',
            'full_address': '1 #4 Tampines Walk Singapore 528523',
            'lat': 1.353496,
            'lng': 103.939684
        },
        {
            'location_id': 90,
            'location_name': 'Tampines Changkat Community Center',
            'full_address': '13 #5 Tampines Street 11 Singapore 529453',
            'lat': 1.345813,
            'lng': 103.947688
        },
        {
            'location_id': 91,
            'location_name': 'Tampines East Community Center',
            'full_address': '10 Tampines Street 23 Singapore 529341',
            'lat': 1.353357,
            'lng': 103.954620
        },
        {
            'location_id': 92,
            'location_name': 'Tampines North Community Center',
            'full_address': '2 Tampines Street 41 Singapore 529204',
            'lat': 1.357365,
            'lng': 103.946603
        },
        {
            'location_id': 93,
            'location_name': 'Tampines West Community Center',
            'full_address': '5 Tampines Avenue 3 Singapore 529705',
            'lat': 1.348751,
            'lng': 103.935633
        },
        {
            'location_id': 94,
            'location_name': 'Tanglin Community Center',
            'full_address': '245 Whitley Road Singapore 297829',
            'lat': 1.323384,
            'lng': 103.826877
        },
        {
            'location_id': 95,
            'location_name': 'Tanjong Pagar Community Center',
            'full_address': '101 Cantonment Road Singapore 089774',
            'lat': 1.276167,
            'lng': 103.841584
        },
        {
            'location_id': 96,
            'location_name': 'Teck Ghee Community Center',
            'full_address': '861 Ang Mo Kio Avenue 10 Singapore 569734',
            'lat': 1.363089,
            'lng': 103.853536
        },
        {
            'location_id': 97,
            'location_name': 'Telok Ayer Hong Lim Green Community Center',
            'full_address': '20 Upper Pickering Street Singapore 058284',
            'lat': 1.286329,
            'lng': 103.846479
        },
        {
            'location_id': 98,
            'location_name': 'Telok Blangah Community Center',
            'full_address': '450 Telok Blangah Street 31 Singapore 108943',
            'lat': 1.274863,
            'lng': 103.807875
        },
        {
            'location_id': 99,
            'location_name': 'Tengah Community Center',
            'full_address': '119 Plantation Crescent Singapore 690119',
            'lat': 1.356752,
            'lng': 103.734500
        },
        {
            'location_id': 100,
            'location_name': 'The Frontier Community Center',
            'full_address': '60 #1 Jurong West Central 3 Singapore 648346',
            'lat': 1.340470,
            'lng': 103.704453
        },
        {
            'location_id': 101,
            'location_name': 'The Serangoon Community Center',
            'full_address': '10 Serangoon North Avenue 2 Singapore 555877',
            'lat': 1.370055,
            'lng': 103.873928
        },
        {
            'location_id': 102,
            'location_name': 'Thomson Community Center',
            'full_address': '194 Upper Thomson Road Singapore 574339',
            'lat': 1.351254,
            'lng': 103.836262
        },
        {
            'location_id': 103,
            'location_name': 'Thomson CC',
            'full_address': '233 #126 Bishan Street 22 Singapore 570233',
            'lat': 1.358588,
            'lng': 103.845523
        },
        {
            'location_id': 104,
            'location_name': 'Tiong Bahru Community Center',
            'full_address': '67A Eu Chin Street Singapore 169715',
            'lat': 1.283453,
            'lng': 103.831883
        },
        {
            'location_id': 105,
            'location_name': 'Toa Payoh Central CC',
            'full_address': '93 Toa Payoh Central Singapore 319194',
            'lat': 1.334935,
            'lng': 103.850205
        },
        {
            'location_id': 106,
            'location_name': 'Toa Payoh East CC',
            'full_address': '160 Lorong 6 Toa Payoh Singapore 319380',
            'lat': 1.336275,
            'lng': 103.854700
        },
        {
            'location_id': 107,
            'location_name': 'Toa Payoh South CC',
            'full_address': '1999 Lorong 8 Toa Payoh Singapore 319258',
            'lat': 1.334890,
            'lng': 103.859379
        },
        {
            'location_id': 108,
            'location_name': 'Toa Payoh West Community Center',
            'full_address': '200 Lorong 2 Toa Payoh Singapore 319642',
            'lat': 1.335383,
            'lng': 103.844831
        },
        {
            'location_id': 109,
            'location_name': 'Ulu Pandan Community Center',
            'full_address': '170 Ghim Moh Road Singapore 279621',
            'lat': 1.312009,
            'lng': 103.789211
        },
        {
            'location_id': 110,
            'location_name': 'West Coast Community Center',
            'full_address': '2 Clementi West Street 2 Singapore 129605',
            'lat': 1.302646,
            'lng': 103.764832
        },
        {
            'location_id': 111,
            'location_name': 'Whampoa Community Center',
            'full_address': '300 Whampoa Drive Singapore 327737',
            'lat': 1.324640,
            'lng': 103.856979
        },
        {
            'location_id': 112,
            'location_name': 'Woodgrove Community Center',
            'full_address': '353 #753 Woodlands Ave 1 Singapore 730353',
            'lat': 1.431771,
            'lng': 103.785007
        },
        {
            'location_id': 113,
            'location_name': 'Woodlands Community Center',
            'full_address': '1 Woodlands Street 81 Singapore 738526',
            'lat': 1.439730,
            'lng': 103.788235
        },
        {
            'location_id': 114,
            'location_name': 'Woodlands Galaxy Community Center',
            'full_address': '31 Woodlands Avenue 6 Singapore 738991',
            'lat': 1.439042,
            'lng': 103.802611
        },
        {
            'location_id': 115,
            'location_name': 'Yew Tee Community Center',
            'full_address': '20 Choa Chu Kang Street 52 Singapore 689286',
            'lat': 1.394918,
            'lng': 103.744728
        },
        {
            'location_id': 116,
            'location_name': 'Yio Chu Kang Community Center',
            'full_address': '50 Ang Mo Kio Street 61 Singapore 569163',
            'lat': 1.381517,
            'lng': 103.841428
        },
        {
            'location_id': 117,
            'location_name': 'Yishun Link Community Center',
            'full_address': '413 #1187 Yishun Ring Road Singapore 760413',
            'lat': 1.425036,
            'lng': 103.846399
        },
        {
            'location_id': 118,
            'location_name': 'Yuhua Community Center',
            'full_address': '90 Boon Lay Way Singapore 609958',
            'lat': 1.339973,
            'lng': 103.737066
        },
        {
            'location_id': 119,
            'location_name': 'Zhenghua Community Center',
            'full_address': '1 Segar Road Singapore 677738',
            'lat': 1.386807,
            'lng': 103.771521
        }
    ]

def find_closest_community_center(user_lat, user_lng):
    """
    Find the closest community center to user's location
    Uses a two-step approach to minimize Google Maps API usage:
    1. Pre-filter using simple distance calculation
    2. Use Google Maps API for top candidates only
    """
    try:
        community_centers = get_community_centers()
        
        # Step 1: Pre-filter using simple Euclidean distance to get top candidates
        # This reduces the number of API calls needed
        candidates = []
        for center in community_centers:
            # Calculate simple distance (lat/lng degrees)
            distance = ((user_lat - center['lat']) ** 2 + (user_lng - center['lng']) ** 2) ** 0.5
            candidates.append((distance, center))
        
        # Sort by distance and take only the top 5 candidates to reduce API usage
        candidates.sort(key=lambda x: x[0])
        top_candidates = [candidate[1] for candidate in candidates[:5]]
        
        # Step 2: Try to use Google Maps Distance Matrix API for accurate results
        gmaps = get_google_maps_client()
        if gmaps and len(top_candidates) > 0:
            try:
                user_location = (user_lat, user_lng)
                destinations = [(center['lat'], center['lng']) for center in top_candidates]
                
                print(f"DEBUG: User coordinates: {user_lat}, {user_lng}")
                print(f"DEBUG: Top 5 candidates by simple distance:")
                for i, candidate in enumerate(top_candidates):
                    simple_dist = candidates[i][0]
                    print(f"  {i+1}. {candidate['location_name']} - Simple distance: {simple_dist:.6f}")
                
                print(f"DEBUG: Using Google Maps API for {len(destinations)} destinations")
                
                matrix = gmaps.distance_matrix(
                    origins=[user_location],
                    destinations=destinations,
                    mode="driving",
                    units="metric",
                    avoid="tolls"
                )
                
                if matrix['status'] == 'OK':
                    print("DEBUG: Google Maps API results:")
                    
                    # Find the center with minimum distance from API results
                    min_distance = float('inf')
                    closest_center = None
                    
                    for i, element in enumerate(matrix['rows'][0]['elements']):
                        if element['status'] == 'OK':
                            distance = element['distance']['value']  # Distance in meters
                            duration = element['duration']['value']  # Duration in seconds
                            print(f"  {top_candidates[i]['location_name']}: {element['distance']['text']} ({element['duration']['text']})")
                            
                            if distance < min_distance:
                                min_distance = distance
                                closest_center = top_candidates[i].copy()
                                closest_center['distance'] = element['distance']['text']
                                closest_center['duration'] = element['duration']['text']
                        else:
                            print(f"  {top_candidates[i]['location_name']}: Error - {element['status']}")
                    
                    if closest_center:
                        print(f"DEBUG: Google Maps chose: {closest_center['location_name']} (driving distance priority)")
                        
                        # Check if the first candidate (closest by straight-line distance) is significantly different
                        first_candidate = top_candidates[0]
                        if first_candidate['location_name'] != closest_center['location_name']:
                            print(f"WARNING: Straight-line closest ({first_candidate['location_name']}) differs from driving closest ({closest_center['location_name']})")
                            print("This may be due to road connectivity, traffic, or routing preferences.")
                            
                            # OVERRIDE: Prioritize straight-line distance over driving convenience
                            print("OVERRIDE: Using straight-line closest instead of driving closest")
                            first_candidate_copy = first_candidate.copy()
                            # Calculate approximate distance for the geographically closest center
                            lat_diff = abs(user_lat - first_candidate['lat'])
                            lng_diff = abs(user_lng - first_candidate['lng'])
                            lat_km = lat_diff * 111.0
                            lng_km = lng_diff * 111.0 * abs(math.cos(math.radians(user_lat)))
                            distance_km = math.sqrt(lat_km**2 + lng_km**2)
                            first_candidate_copy['distance'] = f"~{distance_km:.1f} km"
                            first_candidate_copy['duration'] = "~15-30 min"
                            return first_candidate_copy
                        
                        return closest_center
                else:
                    print(f"Google Maps API returned status: {matrix['status']}")
                    
            except Exception as api_error:
                error_message = str(api_error)
                print(f"Google Maps API error, falling back to simple calculation: {error_message}")
                
                # Check for specific quota errors and provide helpful information
                if "MAX_ELEMENTS_EXCEEDED" in error_message:
                    print("HINT: Google Maps API quota exceeded. Consider upgrading your API plan or reducing request frequency.")
                elif "OVER_QUERY_LIMIT" in error_message:
                    print("HINT: Google Maps API query limit exceeded. Check your daily quota and billing settings.")
                elif "REQUEST_DENIED" in error_message:
                    print("HINT: Google Maps API request denied. Check your API key and enabled services.")
        
        # Fallback: Use simple Euclidean distance calculation with better accuracy
        print("Using fallback distance calculation (simple geographic distance)")
        min_distance = float('inf')
        closest_center = None
        
        # Use the pre-calculated candidates for more efficient fallback
        for distance, center in candidates[:10]:  # Consider top 10 for better accuracy
            # Convert distance to approximate kilometers using the Haversine-like formula
            # This is more accurate than simple Euclidean distance for geographic coordinates
            lat_diff = abs(user_lat - center['lat'])
            lng_diff = abs(user_lng - center['lng'])
            
            # Approximate distance in kilometers (more accurate for Singapore)
            # 1 degree ≈ 111 km, but longitude varies by latitude
            lat_km = lat_diff * 111.0
            lng_km = lng_diff * 111.0 * abs(math.cos(math.radians(user_lat)))
            distance_km = math.sqrt(lat_km**2 + lng_km**2)
            
            if distance_km < min_distance:
                min_distance = distance_km
                closest_center = center.copy()
                closest_center['distance'] = f"~{distance_km:.1f} km"
                closest_center['duration'] = "~15-30 min"  # Rough estimate
        
        if closest_center:
            print(f"DEBUG: Found closest center using fallback: {closest_center['location_name']}")
            return closest_center
        
        # Ultimate fallback
        print("WARNING: Could not calculate distances, returning first center")
        if community_centers:
            fallback = community_centers[0].copy()
            fallback['distance'] = "N/A"
            fallback['duration'] = "N/A"
            return fallback
        
    except Exception as e:
        print(f"Error finding closest community center: {e}")
        # Return first center as ultimate fallback
        centers = get_community_centers()
        if centers:
            fallback = centers[0].copy()
            fallback['distance'] = "N/A"
            fallback['duration'] = "N/A"
            return fallback
    
    return None

def geocode_address(address):
    """
    Convert address to coordinates using Google Geocoding API
    Returns None if API is not available
    """
    try:
        gmaps = get_google_maps_client()
        if not gmaps:
            print("Google Maps API not available for geocoding")
            return None
        
        geocode_result = gmaps.geocode(address)
        
        if geocode_result:
            location = geocode_result[0]['geometry']['location']
            return {
                'lat': location['lat'],
                'lng': location['lng'],
                'formatted_address': geocode_result[0]['formatted_address']
            }
        
        return None
        
    except Exception as e:
        print(f"Error geocoding address: {e}")
        return None
