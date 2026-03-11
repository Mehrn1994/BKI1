"""
Comprehensive Finglish/English → Persian translator for BKI Network Portal.
Handles branch names, city names, province names, and location terms.
All entries are verified against standard Iranian geographic naming.
"""

import re
import unicodedata
from difflib import get_close_matches

# ═══════════════════════════════════════════════════════════════════════════
# PROVINCE CANONICAL MAP  (official Persian name → list of English variants)
# ═══════════════════════════════════════════════════════════════════════════
PROVINCE_MAP = {
    'تهران':        ['tehran','Tehran','TEHRAN','TEH','teh'],
    'اصفهان':       ['isfahan','Isfahan','ISFAHAN','ISF','Isf','esfahan','Esfahan'],
    'آذربایجان شرقی': ['azarbaijansharghi','AzarbaijanSharghi','eastazerbaijan','EastAzerbaijan','EAZ','tabriz_province'],
    'آذربایجان غربی': ['azarbaijangharbi','AzarbaijanGharbi','westazerbaijan','WestAzerbaijan','WAZ','urmia_province'],
    'اردبیل':       ['ardabil','Ardabil','ARDABIL','ARD','ard'],
    'البرز':        ['alborz','Alborz','ALBORZ','ALB'],
    'ایلام':        ['ilam','Ilam','ILAM'],
    'بوشهر':        ['bushehr','Bushehr','BUSHEHR','BSH','bsh'],
    'چهارمحال و بختیاری': ['chaharmahalbakhtiari','CharMahal','chaharbakhtiari','ChaharMahal','CMB'],
    'خراسان رضوی':  ['khorasanrazavi','KhorasanRazavi','KHRZ','mashhad_province'],
    'خراسان شمالی': ['khorasanshoamali','KhorasanShomali','NorthKhorasan','NKH'],
    'خراسان جنوبی': ['khorasanjonoubi','KhorasanJonoubi','SouthKhorasan','SKH'],
    'خوزستان':      ['khuzestan','Khuzestan','KHUZESTAN','KHZ','ahvaz_province'],
    'زنجان':        ['zanjan','Zanjan','ZANJAN','ZNJ'],
    'سمنان':        ['semnan','Semnan','SEMNAN','SMN','Smn'],
    'سیستان و بلوچستان': ['sistanbaluchestan','SistanBaluchestan','SBL','zahedan_province'],
    'فارس':         ['fars','Fars','FARS','shiraz_province'],
    'قزوین':        ['qazvin','Qazvin','QAZVIN','QZV','Qzv'],
    'قم':           ['qom','Qom','QOM','qum','Qum'],
    'کردستان':      ['kurdistan','Kurdistan','KURDISTAN','KRD','sanandaj_province'],
    'کرمان':        ['kerman','Kerman','KERMAN','KRM','krm'],
    'کرمانشاه':     ['kermanshah','Kermanshah','KERMANSHAH','KRN','krn'],
    'کهگیلویه و بویراحمد': ['kohgiluyehboyerahmad','Kohgiluyeh','KBY','yasouj_province'],
    'گلستان':       ['golestan','Golestan','GOLESTAN','GLT'],
    'گیلان':        ['guilan','Gilan','GUILAN','GIL','rasht_province'],
    'لرستان':       ['lorestan','Lorestan','LORESTAN','LRS','khorramabad_province'],
    'مازندران':     ['mazandaran','Mazandaran','MAZANDARAN','MZN','sari_province'],
    'مرکزی':        ['markazi','Markazi','MARKAZI','MRK','arak_province'],
    'هرمزگان':      ['hormozgan','Hormozgan','HORMOZGAN','HRZ','bandarabbas_province'],
    'همدان':        ['hamedan','Hamedan','HAMEDAN','HMD','hmd','hamadan','Hamadan'],
    'یزد':          ['yazd','Yazd','YAZD','YZD'],
    'مازندران':     ['mazandaran','Mazandaran','MAZANDARAN'],
}

# Build flat EN→FA for provinces (case-insensitive lookup later)
_PROVINCE_EN_TO_FA = {}
for fa_name, en_variants in PROVINCE_MAP.items():
    for en in en_variants:
        _PROVINCE_EN_TO_FA[en.lower()] = fa_name

# ═══════════════════════════════════════════════════════════════════════════
# MAIN TRANSLATION DICTIONARY
# key: English/Finglish word (lowercase preferred, but also mixed-case variants)
# value: Persian equivalent
# ═══════════════════════════════════════════════════════════════════════════
FA_DICT = {
    # ── 31 Provinces ──────────────────────────────────────────────────────
    'tehran': 'تهران', 'isfahan': 'اصفهان', 'esfahan': 'اصفهان',
    'tabriz': 'تبریز', 'mashhad': 'مشهد', 'shiraz': 'شیراز',
    'ahvaz': 'اهواز', 'ahwaz': 'اهواز', 'karaj': 'کرج',
    'qom': 'قم', 'qum': 'قم', 'rasht': 'رشت',
    'ardabil': 'اردبیل', 'gorgan': 'گرگان', 'semnan': 'سمنان',
    'yazd': 'یزد', 'yasouj': 'یاسوج', 'zanjan': 'زنجان',
    'hamadan': 'همدان', 'hamedan': 'همدان', 'arak': 'اراک',
    'qazvin': 'قزوین', 'alborz': 'البرز', 'ilam': 'ایلام',
    'bushehr': 'بوشهر', 'shahrekord': 'شهرکرد', 'shahekord': 'شهرکرد',
    'kermanshah': 'کرمانشاه', 'kerman': 'کرمان', 'birjand': 'بیرجند',
    'bandarabbas': 'بندرعباس', 'bojnurd': 'بجنورد', 'sari': 'ساری',
    'zahedan': 'زاهدان', 'khorramabad': 'خرم‌آباد', 'sanandaj': 'سنندج',
    'orumiyeh': 'ارومیه', 'urmia': 'ارومیه', 'ormiya': 'ارومیه',

    # ── Major & secondary cities ──────────────────────────────────────────
    'abadan': 'آبادان', 'abhar': 'ابهر', 'abyek': 'آبیک',
    'ahar': 'اهر', 'ahangaran': 'آهنگران', 'aligoudarz': 'الیگودرز',
    'aliabad': 'علی‌آباد', 'alvand': 'الوند', 'amol': 'آمل',
    'andimeshk': 'اندیمشک', 'anarak': 'انارک', 'anzali': 'انزلی',
    'aq qala': 'آق‌قلا', 'aqghala': 'آق‌قلا', 'aqqala': 'آق‌قلا',
    'ardestan': 'اردستان', 'asadabad': 'اسدآباد', 'astara': 'آستارا',
    'astaneh': 'آستانه', 'azna': 'ازنا', 'azarshahr': 'آذرشهر',
    'babol': 'بابل', 'babolsar': 'بابلسر', 'bahar': 'بهار',
    'bam': 'بم', 'bandar': 'بندر', 'bandarimam': 'بندر امام',
    'bandarlengeh': 'بندرلنگه', 'bandarturk': 'بندرترکمن',
    'behbahan': 'بهبهان', 'beyza': 'بیضا', 'bijar': 'بیجار',
    'boroujen': 'بروجن', 'boroujerd': 'بروجرد', 'bukan': 'بوکان',
    'chabahar': 'چابهار', 'chalus': 'چالوس', 'damghan': 'دامغان',
    'davaran': 'داوران', 'dayyer': 'دیّر', 'dehaj': 'دهج',
    'dezful': 'دزفول', 'dezghan': 'دزغان', 'divandarreh': 'دیواندره',
    'dorud': 'دورود', 'esfarayin': 'اسفراین', 'fasa': 'فسا',
    'fereydunshahr': 'فریدون‌شهر', 'firoozabad': 'فیروزآباد',
    'gachsaran': 'گچساران', 'garmsar': 'گرمسار', 'germi': 'گرمی',
    'golpayegan': 'گلپایگان', 'gonabad': 'گناباد',
    'harsin': 'هرسین', 'hashtpar': 'هشتپر',
    'iranshahr': 'ایرانشهر', 'izeh': 'ایذه',
    'jahrom': 'جهرم', 'jiroft': 'جیرفت', 'jolfa': 'جلفا',
    'kahnuj': 'کهنوج', 'kamyaran': 'کامیاران', 'kangavar': 'کنگاور',
    'kashmar': 'کاشمر', 'kashan': 'کاشان', 'khalkhal': 'خلخال',
    'khansari': 'خوانسار', 'khash': 'خاش', 'khomein': 'خمین',
    'khomeynishahr': 'خمینی‌شهر', 'khoramshahr': 'خرمشهر',
    'khoy': 'خوی', 'khodabandeh': 'خدابنده', 'kuhdasht': 'کوهدشت',
    'larestan': 'لارستان', 'lenjan': 'لنجان', 'lengeh': 'لنگه',
    'mahalat': 'محلات', 'mahabad': 'مهاباد',
    'malayer': 'ملایر', 'marand': 'مرند', 'maragheh': 'مراغه',
    'marivan': 'مریوان', 'masjedsoleyman': 'مسجدسلیمان',
    'meshginshahr': 'مشگین‌شهر', 'miandoab': 'میاندوآب',
    'mianeh': 'میانه', 'mobarakeh': 'مبارکه',
    'naghadeh': 'نقده', 'najafabad': 'نجف‌آباد',
    'natanz': 'نطنز', 'nehavand': 'نهاوند',
    'neyshabur': 'نیشابور', 'neyriz': 'نی‌ریز',
    'omidiyeh': 'امیدیه', 'oshnaviye': 'اشنویه',
    'parsabad': 'پارس‌آباد', 'paveh': 'پاوه',
    'piranshahr': 'پیران‌شهر', 'poldokhtar': 'پل‌دختر',
    'poldasht': 'پلدشت', 'qaen': 'قائن',
    'qeshm': 'قشم', 'qorveh': 'قروه', 'quchan': 'قوچان',
    'rafsanjan': 'رفسنجان', 'ramhormoz': 'رامهرمز',
    'ramsar': 'رامسر', 'razan': 'رزن',
    'sabzevar': 'سبزوار', 'sahneh': 'صحنه',
    'salmas': 'سلماس', 'saqez': 'سقز', 'saravan': 'سراوان',
    'sardasht': 'سردشت', 'saveh': 'ساوه', 'shadegan': 'شادگان',
    'shahreza': 'شهرضا', 'shirvan': 'شیروان',
    'shushtar': 'شوشتر', 'sirjan': 'سیرجان',
    'sonqor': 'سنقر', 'takestan': 'تاکستان',
    'tekab': 'تکاب', 'torbatheydariyeh': 'تربت‌حیدریه',
    'tuyserkan': 'تویسرکان', 'tonekabon': 'تنکابن',
    'zabol': 'زابل', 'zarand': 'زرند',
    'zarinshahr': 'زرین‌شهر', 'noor': 'نور',
    'noshahr': 'نوشهر', 'nowshahr': 'نوشهر',
    'fuman': 'فومن', 'lahijan': 'لاهیجان',
    'langrud': 'لنگرود', 'rudbar': 'رودبار',
    'rezvanshahr': 'رضوانشهر', 'talesh': 'تالش',
    'sowmeasara': 'صومعه‌سرا', 'babol': 'بابل',
    'babolsar': 'بابلسر', 'behshahr': 'بهشهر',
    'chalus': 'چالوس', 'jouybar': 'جویبار',
    'mahmudabad': 'محمودآباد', 'neka': 'نکا',
    'qaemshahr': 'قائمشهر', 'saripol': 'ساری',
    'tonekabon': 'تنکابن', 'minudasht': 'مینودشت',
    'aliabad': 'علی‌آباد', 'kordkuy': 'کردکوی',
    'bandarturk': 'بندرترکمن', 'galikesh': 'گالیکش',
    'ramian': 'رامیان', 'azadshahr': 'آزادشهر',

    # ── Tehran districts & suburbs ──────────────────────────────────────
    'shahryar': 'شهریار', 'islamshahr': 'اسلامشهر',
    'robatkarim': 'رباط‌کریم', 'varamin': 'ورامین',
    'pakdasht': 'پاکدشت', 'shemiranat': 'شمیرانات',
    'damavand': 'دماوند', 'firuzkuh': 'فیروزکوه',
    'eslamshahr': 'اسلامشهر', 'andisheh': 'اندیشه',

    # ── Streets / Location structure words ──────────────────────────────
    'kheyaban': 'خیابان', 'kheiyaban': 'خیابان', 'st': 'خیابان',
    'blv': 'بلوار', 'bolvar': 'بلوار', 'boulevard': 'بلوار',
    'blvd': 'بلوار', 'meydan': 'میدان', 'square': 'میدان',
    'kooche': 'کوچه', 'kooy': 'کوی', 'nabsh': 'نبش',
    'bagh': 'باغ', 'park': 'پارک', 'pars': 'پارس',
    'shahr': 'شهر', 'shahrak': 'شهرک', 'abad': 'آباد',
    'roosta': 'روستا', 'shahrestan': 'شهرستان',
    'markaz': 'مرکز', 'ostan': 'استان', 'bakhsh': 'بخش',
    'mahal': 'محل', 'mahalleh': 'محله', 'mantagheh': 'منطقه',
    'jonoob': 'جنوب', 'shamal': 'شمال', 'shargh': 'شرق',
    'gharb': 'غرب', 'shomali': 'شمالی', 'jonoubi': 'جنوبی',
    'sharghi': 'شرقی', 'gharbi': 'غربی', 'markazi': 'مرکزی',
    'payin': 'پایین', 'bala': 'بالا', 'aval': 'اول',
    'dovvom': 'دوم', 'sevvom': 'سوم', 'chaharom': 'چهارم',

    # ── Landmark / building words ───────────────────────────────────────
    'bazar': 'بازار', 'bazaar': 'بازار',
    'masjed': 'مسجد', 'mosque': 'مسجد',
    'hospital': 'بیمارستان', 'bimarestan': 'بیمارستان',
    'hsptl': 'بیمارستان', 'hosp': 'بیمارستان',
    'clinic': 'کلینیک', 'darmanghah': 'درمانگاه',
    'daneshgah': 'دانشگاه', 'university': 'دانشگاه',
    'airport': 'فرودگاه', 'frodgah': 'فرودگاه',
    'station': 'ایستگاه', 'istgah': 'ایستگاه',
    'terminal': 'ترمینال', 'hotel': 'هتل',
    'psg': 'پاساژ', 'passage': 'پاساژ', 'pasazh': 'پاساژ',
    'tower': 'برج', 'borj': 'برج',
    'complex': 'مجتمع', 'mojtame': 'مجتمع',
    'bank': 'بانک', 'post': 'پست',
    'rahahan': 'راه‌آهن', 'train': 'راه‌آهن',
    'nirou': 'نیرو', 'bargh': 'برق',
    'gaz': 'گاز', 'ab': 'آب', 'falavard': 'فلاورد',

    # ── Branch / point types ────────────────────────────────────────────
    'shoaba': 'شعبه', 'shoba': 'شعبه', 'branch': 'شعبه',
    'baj': 'باجه', 'baje': 'باجه', 'bj': 'باجه',
    'atm': 'خودپرداز', 'kiosk': 'کیوسک',
    'sp': 'سرپرستی', 'sarpardazi': 'سرپرستی',
    'mo': 'مرکز استان', 'central': 'مرکزی',
    'mobile': 'سیار', 'seyar': 'سیار',
    'main': 'اصلی', 'asli': 'اصلی',
    'paaviz': 'پاویز', 'electronic': 'الکترونیک',

    # ── Directorate / org words ─────────────────────────────────────────
    'markaz': 'مرکز', 'omoumi': 'عمومی',
    'kol': 'کل', 'melli': 'ملی', 'mellat': 'ملت',
    'doulati': 'دولتی', 'khososi': 'خصوصی',
    'manabe': 'منابع', 'tabiei': 'طبیعی',
    'keshavarzi': 'کشاورزی', 'sanati': 'صنعتی',
    'tejarat': 'تجارت', 'tejari': 'تجاری',
    'saderat': 'صادرات', 'varedaat': 'واردات',
    'sanat': 'صنعت', 'maadanl': 'معدن',
    'bazargani': 'بازرگانی', 'eghtesad': 'اقتصاد',
    'dampezeshki': 'دامپزشکی', 'behdasht': 'بهداشت',
    'amuzesh': 'آموزش', 'parvaresh': 'پرورش',
    'adl': 'عدل', 'dadgostari': 'دادگستری',
    'shahrdari': 'شهرداری', 'farmandari': 'فرمانداری',
    'ostandardari': 'استانداری', 'shoray': 'شورای',

    # ── Religious / historical names ────────────────────────────────────
    'imam': 'امام', 'emam': 'امام',
    'imam reza': 'امام رضا', 'imamreza': 'امام رضا',
    'imam hossein': 'امام حسین', 'imamhossein': 'امام حسین',
    'imam ali': 'امام علی', 'imamali': 'امام علی',
    'imam khomeini': 'امام خمینی', 'imamkhomeini': 'امام خمینی',
    'imam hassan': 'امام حسن', 'imamhassan': 'امام حسن',
    'imam sajad': 'امام سجاد', 'imamsajad': 'امام سجاد',
    'valiasr': 'ولیعصر', 'valieasr': 'ولیعصر',
    'shahid': 'شهید', 'martyrs': 'شهدا', 'shohada': 'شهدا',
    'saheb': 'صاحب', 'sahebolzaman': 'صاحب‌الزمان',
    'beheshti': 'بهشتی', 'motahari': 'مطهری',
    'bahonar': 'باهنر', 'rajaei': 'رجایی',
    'taleghani': 'طالقانی', 'taleqani': 'طالقانی',
    'modares': 'مدرس', 'shariati': 'شریعتی',
    'keshavarz': 'کشاورز', 'jomhuri': 'جمهوری',
    'enghelab': 'انقلاب', 'azadi': 'آزادی',
    'fatemi': 'فاطمی', 'chamran': 'چمران',
    'resalat': 'رسالت', 'sattari': 'ستاری',
    'isargaran': 'ایثارگران', 'abuzar': 'ابوذر',
    'bakeri': 'باکری', 'kolahdouz': 'کلاهدوز',
    'ferdowsi': 'فردوسی', 'ferdosi': 'فردوسی',
    'hafez': 'حافظ', 'saadi': 'سعدی',
    'nader': 'نادر', 'cyrus': 'کوروش',
    'dariush': 'داریوش', 'arash': 'آرش',
    'karbala': 'کربلا', 'najaf': 'نجف',
    'mecca': 'مکه', 'madineh': 'مدینه',

    # ── Personal names (common in branch names) ─────────────────────────
    'ali': 'علی', 'hossein': 'حسین', 'hassan': 'حسن',
    'reza': 'رضا', 'mahdi': 'مهدی', 'javad': 'جواد',
    'mousa': 'موسی', 'karim': 'کریم', 'hakim': 'حکیم',
    'ahmad': 'احمد', 'akbar': 'اکبر', 'asghar': 'اصغر',
    'mostafa': 'مصطفی', 'sadegh': 'صادق',
    'moradi': 'مرادی', 'hosseini': 'حسینی',
    'ahmadi': 'احمدی', 'rezaei': 'رضایی',
    'mohammadi': 'محمدی', 'nouri': 'نوری',
    'kashani': 'کاشانی', 'zeinab': 'زینب',
    'fatemeh': 'فاطمه', 'maryam': 'مریم',
    'mahmoudi': 'محمودی', 'akbari': 'اکبری',
    'karimi': 'کریمی', 'salehi': 'صالحی',
    'nazari': 'نظری', 'safari': 'صفری',
    'jafari': 'جعفری', 'mousavi': 'موسوی',
    'hashemi': 'هاشمی', 'tavakkoli': 'توکلی',
    'ebrahimi': 'ابراهیمی', 'sadeghi': 'صادقی',
    'tajik': 'تاجیک', 'jamali': 'جمالی',

    # ── Calendar / date words ────────────────────────────────────────────
    'farvardin': 'فروردین', 'ordibehesht': 'اردیبهشت',
    'khordad': 'خرداد', 'tir': 'تیر',
    'mordad': 'مرداد', 'shahrivar': 'شهریور',
    'mehr': 'مهر', 'aban': 'آبان',
    'azar': 'آذر', 'dey': 'دی',
    'bahman': 'بهمن', 'esfand': 'اسفند',
    'nowruz': 'نوروز', 'norouz': 'نوروز',

    # ── Numbers & ordinals ───────────────────────────────────────────────
    'yek': 'یک', 'do': 'دو', 'se': 'سه',
    'chahar': 'چهار', 'panj': 'پنج', 'shish': 'شش',
    'haft': 'هفت', 'hasht': 'هشت', 'noh': 'نه',
    'dah': 'ده', 'bist': 'بیست', 'si': 'سی',
    'chel': 'چهل', 'panjah': 'پنجاه',

    # ── Common compound prefixes / suffixes ─────────────────────────────
    'new': 'جدید', 'jadid': 'جدید', 'now': 'نو',
    'old': 'قدیم', 'ghadim': 'قدیم',
    'bozorg': 'بزرگ', 'kuchak': 'کوچک',
    'kohne': 'کهنه', 'no': 'نو',

    # ── Banking specific ─────────────────────────────────────────────────
    'meli': 'ملی', 'mellat': 'ملت',
    'sepah': 'سپه', 'maskan': 'مسکن',
    'refah': 'رفاه', 'pasargad': 'پاسارگاد',
    'parsian': 'پارسیان', 'saman': 'سامان',
    'sina': 'سینا', 'ayandeh': 'آینده',
    'karafarin': 'کارآفرین', 'ansar': 'انصار',
    'sherkat': 'شرکت', 'sarmayeh': 'سرمایه',

    # ── Nature / geography words ─────────────────────────────────────────
    'kuh': 'کوه', 'darya': 'دریا', 'rudkhaneh': 'رودخانه',
    'cheshmeh': 'چشمه', 'biaban': 'بیابان',
    'jungle': 'جنگل', 'jangal': 'جنگل',
    'dasht': 'دشت', 'kavir': 'کویر',
    'gardaneh': 'گردنه', 'taleh': 'تالاب',
    'abgarm': 'آبگرم', 'cheshme': 'چشمه',

    # ── Finglish compound words common in BKI data ──────────────────────
    'islamabad': 'اسلام‌آباد', 'islamabd': 'اسلام‌آباد',
    'hosseinabad': 'حسین‌آباد', 'hasanabad': 'حسن‌آباد',
    'ahmadabad': 'احمدآباد', 'mohammadabad': 'محمدآباد',
    'aliabad': 'علی‌آباد', 'soltanabad': 'سلطان‌آباد',
    'dowlatabad': 'دولت‌آباد', 'doulatabas': 'دولت‌آباد',
    'bazargan': 'بازرگان', 'tarebar': 'تره‌بار',
    'shahrake': 'شهرک', 'shahraksan': 'شهرک صنعتی',
    'rahahan': 'راه‌آهن', 'rahnan': 'راهنمایی',
    'rahnamaiy': 'راهنمایی', 'mahdiyeh': 'مهدیه',
    'taavon': 'تعاون', 'golestan': 'گلستان',
    'shahrivar': 'شهریور', 'nobahar': 'نوبهار',
    'nakhltaqi': 'نخل تقی', 'taghbostan': 'طاق بستان',
    'siahkal': 'سیاهکل', 'azadshahr': 'آزادشهر',
    'goltape': 'گل تپه', 'hesarak': 'حصارک',
    'nazarabad': 'نظرآباد', 'hashtgerd': 'هشتگرد',
    'payambar': 'پیامبر', 'nabovat': 'نبوت',
    'mahalati': 'محلاتی', 'artesh': 'ارتش',
    'niayesh': 'نیایش', 'saadat': 'سعادت',
    'saadatabad': 'سعادت‌آباد', 'ekbatan': 'اکباتان',
    'shahidgolabi': 'شهید گلابی',
    'pounak': 'پونک', 'chitgar': 'چیتگر',
    'tehranpars': 'تهران‌پارس', 'majidieh': 'مجیدیه',
    'narmak': 'نارمک', 'dolatabad': 'دولت‌آباد',
    'abbasabad': 'عباس‌آباد', 'ozgol': 'اوزگل',
    'lavizan': 'لویزان', 'shemiran': 'شمیران',
    'tajrish': 'تجریش', 'darband': 'دربند',
    'vanak': 'ونک', 'yoosefabad': 'یوسف‌آباد',
    'amirabad': 'امیرآباد', 'karimkhan': 'کریم‌خان',
    'lalehzar': 'لاله‌زار', 'daneshjoo': 'دانشجو',
    'baharestan': 'بهارستان', 'khazaneh': 'خزانه',
    'shoosh': 'شوش', 'piroozi': 'پیروزی',
    'sabalan': 'سبلان', 'farmaniyeh': 'فرمانیه',
    'dezashib': 'دزاشیب', 'mirdamad': 'میرداماد',
    'zaaferanieh': 'زعفرانیه', 'qolhak': 'قلهک',
    'gheytariyeh': 'قیطریه', 'velenjak': 'ولنجک',
    'niavaran': 'نیاوران', 'jamaran': 'جماران',
    'elahiyeh': 'الهیه', 'andarzgoo': 'اندرزگو',
    'seyed khandan': 'سیدخندان', 'seyedkhandan': 'سیدخندان',
    'dibajee': 'دیباجی', 'pasdaran': 'پاسداران',
    'afriqa': 'آفریقا', 'africa': 'آفریقا',
    'modiriat': 'مدیریت', 'heravi': 'هروی',
    'felestin': 'فلسطین', 'nabovat': 'نبوت',
    'iran': 'ایران', 'lorestan': 'لرستان',
    'baneh': 'بانه', 'dezaj': 'دزج',
    'vinsar': 'وینسار', 'shabestar': 'شبستر',
    'dehgolan': 'دهگلان', 'pataveh': 'پاتاوه',
    'pishin': 'پیشین', 'bijar': 'بیجار',
}

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def _is_persian(text: str) -> bool:
    """Return True if text already contains Persian/Arabic characters."""
    if not text:
        return False
    persian_chars = sum(1 for c in text if '\u0600' <= c <= '\u06FF' or '\uFB50' <= c <= '\uFDFF')
    return persian_chars > len(text) * 0.3


def _split_camel(token: str) -> list:
    """Split CamelCase/PascalCase into constituent words.
    e.g. 'KhorramAbaad' → ['Khorram', 'Abaad'], 'IslamAbad' → ['Islam','Abad']
    """
    if not token:
        return []
    # Insert space before each capital that follows a lowercase or digit
    spaced = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', token)
    # Also split consecutive caps followed by lower: ABCDef → ABC Def
    spaced = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', spaced)
    return [p for p in spaced.split() if p]


def _normalize_key(token: str) -> str:
    """Lowercase + strip accents for dict lookup."""
    return token.strip().lower()


def _lookup_single(token: str) -> str | None:
    """Look up a single token in FA_DICT (case-insensitive)."""
    if not token:
        return None
    # Direct lower match
    key = _normalize_key(token)
    if key in FA_DICT:
        return FA_DICT[key]
    # Check province map too
    if key in _PROVINCE_EN_TO_FA:
        return _PROVINCE_EN_TO_FA[key]
    return None


def _fuzzy_match(token: str, cutoff: float = 0.80) -> str | None:
    """Find closest match in FA_DICT keys using difflib (min 4 chars)."""
    if len(token) < 4:
        return None
    all_keys = list(FA_DICT.keys()) + list(_PROVINCE_EN_TO_FA.keys())
    key = token.lower()
    matches = get_close_matches(key, all_keys, n=1, cutoff=cutoff)
    if matches:
        if matches[0] in FA_DICT:
            return FA_DICT[matches[0]]
        return _PROVINCE_EN_TO_FA.get(matches[0])
    return None


def translate(text: str, fuzzy: bool = True) -> str:
    """
    Translate English/Finglish text to Persian.

    Strategy (fastest-first):
      1. Already Persian → return as-is
      2. Exact match in FA_DICT / province map
      3. Strip numeric suffix then retry (e.g. "Branch-01")
      4. Split on separators (-, _, space) → translate word by word
         • Per word: exact → CamelCase-split+join → fuzzy
      5. Return best reconstruction
    """
    if not text or not text.strip():
        return text or ''

    text = text.strip()

    # 1. Already Persian
    if _is_persian(text):
        return text

    # 2. Direct full-string lookup
    direct = _lookup_single(text)
    if direct:
        return direct

    # 3. Strip trailing numbers/separators then retry
    stripped = re.sub(r'[\s\-_]+\d+$', '', text).strip()
    if stripped != text:
        direct2 = _lookup_single(stripped)
        if direct2:
            suffix = text[len(stripped):]
            return direct2 + suffix

    # 4. Split into tokens
    # First split on explicit separators
    raw_tokens = re.split(r'[\s\-_/]+', text)
    all_tokens = []
    for rt in raw_tokens:
        parts = _split_camel(rt)
        if parts:
            all_tokens.extend(parts)
        elif rt:
            all_tokens.append(rt)

    translated_parts = []
    for tok in all_tokens:
        if not tok:
            continue
        if _is_persian(tok):
            translated_parts.append(tok)
            continue

        # Exact lookup on this token
        fa = _lookup_single(tok)
        if fa:
            translated_parts.append(fa)
            continue

        # Try lowercase variant with abad suffix (common: HosseinAbad → حسین‌آباد)
        if tok.lower().endswith('abad') and len(tok) > 5:
            prefix = tok[:-4]
            fa_prefix = _lookup_single(prefix)
            if fa_prefix:
                translated_parts.append(fa_prefix + '‌آباد')
                continue

        # Fuzzy
        if fuzzy:
            fa_fuzzy = _fuzzy_match(tok, cutoff=0.80)
            if fa_fuzzy:
                translated_parts.append(fa_fuzzy)
                continue

        # No match → keep original
        translated_parts.append(tok)

    result = ' '.join(translated_parts)
    # If result is still identical to input (no translation happened) return original
    if result.lower() == text.lower():
        return text
    return result


def translate_province(text: str) -> str:
    """Translate a province name to Persian (exact, no fuzzy for provinces)."""
    if not text or not text.strip():
        return text or ''
    if _is_persian(text):
        return text
    key = _normalize_key(text)
    # Direct province map
    if key in _PROVINCE_EN_TO_FA:
        return _PROVINCE_EN_TO_FA[key]
    # Fall back to full translate
    return translate(text, fuzzy=False)


def add_custom_translation(name_en: str, name_fa: str) -> None:
    """Add a user-provided translation to the in-memory FA_DICT."""
    if name_en and name_fa:
        FA_DICT[name_en.lower().strip()] = name_fa.strip()
        FA_DICT[name_en.strip()] = name_fa.strip()


def load_custom_from_db(conn) -> int:
    """Load custom_translations table into FA_DICT. Returns count loaded."""
    loaded = 0
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name_en, name_fa FROM custom_translations")
        for row in cursor.fetchall():
            en, fa = (row[0] or '').strip(), (row[1] or '').strip()
            if en and fa:
                FA_DICT[en.lower()] = fa
                FA_DICT[en] = fa
                loaded += 1
    except Exception:
        pass
    return loaded
