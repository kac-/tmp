import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.OpenOption;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import javax.servlet.AsyncContext;
import javax.servlet.AsyncEvent;
import javax.servlet.AsyncListener;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

public class Nxt extends HttpServlet
{
  static final String VERSION = "0.4.2";
  static final long GENESIS_BLOCK_ID = 2680262203532249785L;
  static final long CREATOR_ID = 1739068987193023818L;
  static final int BLOCK_HEADER_LENGTH = 224;
  static final int MAX_PAYLOAD_LENGTH = 32640;
  static final long initialBaseTarget = 153722867L;
  static final long maxBaseTarget = 153722867000000000L;
  static final BigInteger two64 = new BigInteger("18446744073709551616");
  static long epochBeginning;
  static final String alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
  static FileChannel blockchainChannel;
  static String myAddress;
  static String myHallmark;
  static HashSet<String> allowedUserHosts;
  static HashSet<String> allowedBotHosts;
  static int blacklistingPeriod;
  static boolean wakeKharon;
  static boolean logPeerCommunication;
  static int transactionCounter;
  static HashMap<Long, Nxt.Transaction> transactions;
  static ConcurrentHashMap<Long, Nxt.Transaction> unconfirmedTransactions = new ConcurrentHashMap();
  static ConcurrentHashMap<Long, Nxt.Transaction> doubleSpendingTransactions = new ConcurrentHashMap();
  static HashSet<String> wellKnownPeers = new HashSet();
  static int maxNumberOfConnectedPublicPeers;
  static int connectTimeout;
  static int readTimeout;
  static int pushThreshold;
  static int pullThreshold;
  static int peerCounter;
  static HashMap<String, Nxt.Peer> peers = new HashMap();
  static int blockCounter;
  static HashMap<Long, Nxt.Block> blocks;
  static long lastBlock;
  static Nxt.Peer lastBlockchainFeeder;
  static HashMap<Long, Nxt.Account> accounts = new HashMap();
  static HashMap<String, Nxt.Alias> aliases = new HashMap();
  static HashMap<Long, Nxt.Alias> aliasIdToAliasMappings = new HashMap();
  static HashMap<Long, Nxt.Asset> assets = new HashMap();
  static HashMap<String, Long> assetNameToIdMappings = new HashMap();
  static HashMap<Long, Nxt.AskOrder> askOrders = new HashMap();
  static HashMap<Long, Nxt.BidOrder> bidOrders = new HashMap();
  static HashMap<Long, TreeSet<Nxt.AskOrder>> sortedAskOrders = new HashMap();
  static HashMap<Long, TreeSet<Nxt.BidOrder>> sortedBidOrders = new HashMap();
  static ConcurrentHashMap<String, Nxt.User> users = new ConcurrentHashMap();
  static ExecutorService cachedThreadPool = Executors.newCachedThreadPool();
  static ScheduledExecutorService scheduledThreadPool = Executors.newScheduledThreadPool(7);
  static HashMap<Nxt.Account, Nxt.Block> lastBlocks = new HashMap();
  static HashMap<Nxt.Account, BigInteger> hits = new HashMap();

  static int getEpochTime(long paramLong)
  {
    return (int)((paramLong - epochBeginning + 500L) / 1000L);
  }

  static void logMessage(String paramString)
  {
    System.out.println(new SimpleDateFormat("[yyyy-MM-dd HH:mm:ss.SSS] ").format(new Date()) + paramString);
  }

  static byte[] convert(String paramString)
  {
    byte[] arrayOfByte = new byte[paramString.length() / 2];
    for (int i = 0; i < arrayOfByte.length; ++i)
      arrayOfByte[i] = (byte)Integer.parseInt(paramString.substring(i * 2, i * 2 + 2), 16);
    return arrayOfByte;
  }

  static String convert(byte[] paramArrayOfByte)
  {
    StringBuilder localStringBuilder = new StringBuilder();
    for (int i = 0; i < paramArrayOfByte.length; ++i)
    {
      int j;
      localStringBuilder.append("0123456789abcdefghijklmnopqrstuvwxyz".charAt((j = paramArrayOfByte[i] & 0xFF) >> 4)).append("0123456789abcdefghijklmnopqrstuvwxyz".charAt(j & 0xF));
    }
    return localStringBuilder.toString();
  }

  static String convert(long paramLong)
  {
    BigInteger localBigInteger = BigInteger.valueOf(paramLong);
    if (paramLong < 0L)
      localBigInteger = localBigInteger.add(two64);
    return localBigInteger.toString();
  }

  static void matchOrders(long paramLong)
    throws Exception
  {
    TreeSet localTreeSet1 = (TreeSet)sortedAskOrders.get(Long.valueOf(paramLong));
    TreeSet localTreeSet2 = (TreeSet)sortedBidOrders.get(Long.valueOf(paramLong));
    synchronized (askOrders)
    {
      synchronized (bidOrders)
      {
        do
        {
          Nxt.AskOrder localAskOrder = (Nxt.AskOrder)localTreeSet1.first();
          Nxt.BidOrder localBidOrder = (Nxt.BidOrder)localTreeSet2.first();
          if (localAskOrder.price > localBidOrder.price)
            break;
          int i = (localAskOrder.quantity < localBidOrder.quantity) ? localAskOrder.quantity : localBidOrder.quantity;
          long l = ((localAskOrder.height < localBidOrder.height) || ((localAskOrder.height == localBidOrder.height) && (localAskOrder.id < localBidOrder.id))) ? localAskOrder.price : localBidOrder.price;
          if (localAskOrder.quantity -= i == 0)
          {
            askOrders.remove(Long.valueOf(localAskOrder.id));
            localTreeSet1.remove(localAskOrder);
          }
          synchronized (localAskOrder.account)
          {
            localAskOrder.account.setBalance(localAskOrder.account.balance + i * l);
            localAskOrder.account.setUnconfirmedBalance(localAskOrder.account.unconfirmedBalance + i * l);
          }
          if (localBidOrder.quantity -= i == 0)
          {
            bidOrders.remove(Long.valueOf(localBidOrder.id));
            localTreeSet2.remove(localBidOrder);
          }
          synchronized (localBidOrder.account)
          {
            Integer localInteger = (Integer)localBidOrder.account.assetBalances.get(Long.valueOf(paramLong));
            if (localInteger == null)
            {
              localBidOrder.account.assetBalances.put(Long.valueOf(paramLong), Integer.valueOf(i));
              localBidOrder.account.unconfirmedAssetBalances.put(Long.valueOf(paramLong), Integer.valueOf(i));
            }
            else
            {
              localBidOrder.account.assetBalances.put(Long.valueOf(paramLong), Integer.valueOf(localInteger.intValue() + i));
              localBidOrder.account.unconfirmedAssetBalances.put(Long.valueOf(paramLong), Integer.valueOf(((Integer)localBidOrder.account.unconfirmedAssetBalances.get(Long.valueOf(paramLong))).intValue() + i));
            }
          }
          if (localTreeSet1.isEmpty())
            break;
        }
        while (!localTreeSet2.isEmpty());
      }
    }
  }

  public void init(ServletConfig paramServletConfig)
    throws ServletException
  {
    logMessage("Nxt 0.4.2 started.");
    try
    {
      Calendar localCalendar = Calendar.getInstance();
      localCalendar.set(15, 0);
      localCalendar.set(1, 2013);
      localCalendar.set(2, 10);
      localCalendar.set(5, 24);
      localCalendar.set(11, 12);
      localCalendar.set(12, 0);
      localCalendar.set(13, 0);
      localCalendar.set(14, 0);
      epochBeginning = localCalendar.getTimeInMillis();
      String str1 = paramServletConfig.getInitParameter("blockchainStoragePath");
      logMessage("\"blockchainStoragePath\" = \"" + str1 + "\"");
      blockchainChannel = FileChannel.open(Paths.get(str1, new String[0]), new OpenOption[] { StandardOpenOption.READ, StandardOpenOption.WRITE });
      myAddress = paramServletConfig.getInitParameter("myAddress");
      logMessage("\"myAddress\" = \"" + myAddress + "\"");
      if (myAddress != null)
        myAddress = myAddress.trim();
      myHallmark = paramServletConfig.getInitParameter("myHallmark");
      logMessage("\"myHallmark\" = \"" + myHallmark + "\"");
      if (myHallmark != null)
        myHallmark = myHallmark.trim();
      String str2 = paramServletConfig.getInitParameter("wellKnownPeers");
      logMessage("\"wellKnownPeers\" = \"" + str2 + "\"");
      if (str2 != null)
        for (str3 : str2.split(";"))
        {
          str3 = str3.trim();
          if (str3.length() <= 0)
            continue;
          wellKnownPeers.add(str3);
          Nxt.Peer.addPeer(str3, str3);
        }
      String str3 = paramServletConfig.getInitParameter("maxNumberOfConnectedPublicPeers");
      logMessage("\"maxNumberOfConnectedPublicPeers\" = \"" + str3 + "\"");
      try
      {
        maxNumberOfConnectedPublicPeers = Integer.parseInt(str3);
      }
      catch (Exception localException2)
      {
        maxNumberOfConnectedPublicPeers = 20;
      }
      String str4 = paramServletConfig.getInitParameter("connectTimeout");
      logMessage("\"connectTimeout\" = \"" + str4 + "\"");
      try
      {
        connectTimeout = Integer.parseInt(str4);
      }
      catch (Exception localException3)
      {
        connectTimeout = 1000;
      }
      String str5 = paramServletConfig.getInitParameter("readTimeout");
      logMessage("\"readTimeout\" = \"" + str5 + "\"");
      try
      {
        readTimeout = Integer.parseInt(str5);
      }
      catch (Exception localException4)
      {
        readTimeout = 1000;
      }
      ??? = paramServletConfig.getInitParameter("pushThreshold");
      logMessage("\"pushThreshold\" = \"" + (String)??? + "\"");
      try
      {
        pushThreshold = Integer.parseInt((String)???);
      }
      catch (Exception localException5)
      {
        pushThreshold = 0;
      }
      String str6 = paramServletConfig.getInitParameter("pullThreshold");
      logMessage("\"pullThreshold\" = \"" + str6 + "\"");
      try
      {
        pullThreshold = Integer.parseInt(str6);
      }
      catch (Exception localException6)
      {
        pullThreshold = 0;
      }
      String str7 = paramServletConfig.getInitParameter("allowedUserHosts");
      logMessage("\"allowedUserHosts\" = \"" + str7 + "\"");
      if ((str7 != null) && (!str7.trim().equals("*")))
      {
        allowedUserHosts = new HashSet();
        for (str8 : str7.split(";"))
        {
          str8 = str8.trim();
          if (str8.length() <= 0)
            continue;
          allowedUserHosts.add(str8);
        }
      }
      String str8 = paramServletConfig.getInitParameter("allowedBotHosts");
      logMessage("\"allowedBotHosts\" = \"" + str8 + "\"");
      if ((str8 != null) && (!str8.trim().equals("*")))
      {
        allowedBotHosts = new HashSet();
        for (str9 : str8.split(";"))
        {
          str9 = str9.trim();
          if (str9.length() <= 0)
            continue;
          allowedBotHosts.add(str9);
        }
      }
      String str9 = paramServletConfig.getInitParameter("blacklistingPeriod");
      logMessage("\"blacklistingPeriod\" = \"" + str9 + "\"");
      try
      {
        blacklistingPeriod = Integer.parseInt(str9) * 1000;
      }
      catch (Exception localException7)
      {
        blacklistingPeriod = 300000;
      }
      String str10 = paramServletConfig.getInitParameter("wakeKharon");
      logMessage("\"wakeKharon\" = \"" + str10 + "\"");
      try
      {
        wakeKharon = Boolean.parseBoolean(str10);
      }
      catch (Exception localException8)
      {
      }
      String str11 = paramServletConfig.getInitParameter("logPeerCommunication");
      logMessage("\"logPeerCommunication\" = \"" + str11 + "\"");
      try
      {
        logPeerCommunication = Boolean.parseBoolean(str11);
      }
      catch (Exception localException9)
      {
      }
      Object localObject4;
      Object localObject3;
      try
      {
        logMessage("Loading transactions...");
        Nxt.Transaction.loadTransactions("transactions.nxt");
        logMessage("...Done");
      }
      catch (FileNotFoundException localFileNotFoundException1)
      {
        transactions = new HashMap();
        ??? = new long[] { new BigInteger("163918645372308887").longValue(), new BigInteger("620741658595224146").longValue(), new BigInteger("723492359641172834").longValue(), new BigInteger("818877006463198736").longValue(), new BigInteger("1264744488939798088").longValue(), new BigInteger("1600633904360147460").longValue(), new BigInteger("1796652256451468602").longValue(), new BigInteger("1814189588814307776").longValue(), new BigInteger("1965151371996418680").longValue(), new BigInteger("2175830371415049383").longValue(), new BigInteger("2401730748874927467").longValue(), new BigInteger("2584657662098653454").longValue(), new BigInteger("2694765945307858403").longValue(), new BigInteger("3143507805486077020").longValue(), new BigInteger("3684449848581573439").longValue(), new BigInteger("4071545868996394636").longValue(), new BigInteger("4277298711855908797").longValue(), new BigInteger("4454381633636789149").longValue(), new BigInteger("4747512364439223888").longValue(), new BigInteger("4777958973882919649").longValue(), new BigInteger("4803826772380379922").longValue(), new BigInteger("5095742298090230979").longValue(), new BigInteger("5271441507933314159").longValue(), new BigInteger("5430757907205901788").longValue(), new BigInteger("5491587494620055787").longValue(), new BigInteger("5622658764175897611").longValue(), new BigInteger("5982846390354787993").longValue(), new BigInteger("6290807999797358345").longValue(), new BigInteger("6785084810899231190").longValue(), new BigInteger("6878906112724074600").longValue(), new BigInteger("7017504655955743955").longValue(), new BigInteger("7085298282228890923").longValue(), new BigInteger("7446331133773682477").longValue(), new BigInteger("7542917420413518667").longValue(), new BigInteger("7549995577397145669").longValue(), new BigInteger("7577840883495855927").longValue(), new BigInteger("7579216551136708118").longValue(), new BigInteger("8278234497743900807").longValue(), new BigInteger("8517842408878875334").longValue(), new BigInteger("8870453786186409991").longValue(), new BigInteger("9037328626462718729").longValue(), new BigInteger("9161949457233564608").longValue(), new BigInteger("9230759115816986914").longValue(), new BigInteger("9306550122583806885").longValue(), new BigInteger("9433259657262176905").longValue(), new BigInteger("9988839211066715803").longValue(), new BigInteger("10105875265190846103").longValue(), new BigInteger("10339765764359265796").longValue(), new BigInteger("10738613957974090819").longValue(), new BigInteger("10890046632913063215").longValue(), new BigInteger("11494237785755831723").longValue(), new BigInteger("11541844302056663007").longValue(), new BigInteger("11706312660844961581").longValue(), new BigInteger("12101431510634235443").longValue(), new BigInteger("12186190861869148835").longValue(), new BigInteger("12558748907112364526").longValue(), new BigInteger("13138516747685979557").longValue(), new BigInteger("13330279748251018740").longValue(), new BigInteger("14274119416917666908").longValue(), new BigInteger("14557384677985343260").longValue(), new BigInteger("14748294830376619968").longValue(), new BigInteger("14839596582718854826").longValue(), new BigInteger("15190676494543480574").longValue(), new BigInteger("15253761794338766759").longValue(), new BigInteger("15558257163011348529").longValue(), new BigInteger("15874940801139996458").longValue(), new BigInteger("16516270647696160902").longValue(), new BigInteger("17156841960446798306").longValue(), new BigInteger("17228894143802851995").longValue(), new BigInteger("17240396975291969151").longValue(), new BigInteger("17491178046969559641").longValue(), new BigInteger("18345202375028346230").longValue(), new BigInteger("18388669820699395594").longValue() };
        int[] arrayOfInt = { 36742, 1970092, 349130, 24880020, 2867856, 9975150, 2690963, 7648, 5486333, 34913026, 997515, 30922966, 6650, 44888, 2468850, 49875751, 49875751, 9476393, 49875751, 14887912, 528683, 583546, 7315, 19925363, 29856290, 5320, 4987575, 5985, 24912938, 49875751, 2724712, 1482474, 200999, 1476156, 498758, 987540, 16625250, 5264386, 15487585, 2684479, 14962725, 34913026, 5033128, 2916900, 49875751, 4962637, 170486123, 8644631, 22166945, 6668388, 233751, 4987575, 11083556, 1845403, 49876, 3491, 3491, 9476, 49876, 6151, 682633, 49875751, 482964, 4988, 49875751, 4988, 9144, 503745, 49875751, 52370, 29437998, 585375, 9975150 };
        byte[][] arrayOfByte = { { 41, 115, -41, 7, 37, 21, -3, -41, 120, 119, 63, -101, 108, 48, -117, 1, -43, 32, 85, 95, 65, 42, 92, -22, 123, -36, 6, -99, -61, -53, 93, 7, 23, 8, -30, 65, 57, -127, -2, 42, -92, -104, 11, 72, -66, 108, 17, 113, 99, -117, -75, 123, 110, 107, 119, -25, 67, 64, 32, 117, 111, 54, 82, -14 }, { 118, 43, 84, -91, -110, -102, 100, -40, -33, -47, -13, -7, -88, 2, -42, -66, -38, -22, 105, -42, -69, 78, 51, -55, -48, 49, -89, 116, -96, -104, -114, 14, 94, 58, -115, -8, 111, -44, 76, -104, 54, -15, 126, 31, 6, -80, 65, 6, 124, 37, -73, 92, 4, 122, 122, -108, 1, -54, 31, -38, -117, -1, -52, -56 }, { 79, 100, -101, 107, -6, -61, 40, 32, -98, 32, 80, -59, -76, -23, -62, 38, 4, 105, -106, -105, -121, -85, 13, -98, -77, 126, -125, 103, 12, -41, 1, 2, 45, -62, -69, 102, 116, -61, 101, -14, -68, -31, 9, 110, 18, 2, 33, -98, -37, -128, 17, -19, 124, 125, -63, 92, -70, 96, 96, 125, 91, 8, -65, -12 }, { 58, -99, 14, -97, -75, -10, 110, -102, 119, -3, -2, -12, -82, -33, -27, 118, -19, 55, -109, 6, 110, -10, 108, 30, 94, -113, -5, -98, 19, 12, -125, 14, -77, 33, -128, -21, 36, -120, -12, -81, 64, 95, 67, -3, 100, 122, -47, 127, -92, 114, 68, 72, 2, -40, 80, 117, -17, -56, 103, 37, -119, 3, 22, 23 }, { 76, 22, 121, -4, -77, -127, 18, -102, 7, 94, -73, -96, 108, -11, 81, -18, -37, -85, -75, 86, -119, 94, 126, 95, 47, -36, -16, -50, -9, 95, 60, 15, 14, 93, -108, -83, -67, 29, 2, -53, 10, -118, -51, -46, 92, -23, -56, 60, 46, -90, -84, 126, 60, 78, 12, 53, 61, 121, -6, 77, 112, 60, 40, 63 }, { 64, 121, -73, 68, 4, -103, 81, 55, -41, -81, -63, 10, 117, -74, 54, -13, -85, 79, 21, 116, -25, -12, 21, 120, -36, -80, 53, -78, 103, 25, 55, 6, -75, 96, 80, -125, -11, -103, -20, -41, 121, -61, -40, 63, 24, -81, -125, 90, -12, -40, -52, -1, -114, 14, -44, -112, -80, 83, -63, 88, -107, -10, -114, -86 }, { -81, 126, -41, -34, 66, -114, -114, 114, 39, 32, -125, -19, -95, -50, -111, -51, -33, 51, 99, -127, 58, 50, -110, 44, 80, -94, -96, 68, -69, 34, 86, 3, -82, -69, 28, 20, -111, 69, 18, -41, -23, 27, -118, 20, 72, 21, -112, 53, -87, -81, -47, -101, 123, -80, 99, -15, 33, -120, -8, 82, 80, -8, -10, -45 }, { 92, 77, 53, -87, 26, 13, -121, -39, -62, -42, 47, 4, 7, 108, -15, 112, 103, 38, -50, -74, 60, 56, -63, 43, -116, 49, -106, 69, 118, 65, 17, 12, 31, 127, -94, 55, -117, -29, -117, 31, -95, -110, -2, 63, -73, -106, -88, -41, -19, 69, 60, -17, -16, 61, 32, -23, 88, -106, -96, 37, -96, 114, -19, -99 }, { 68, -26, 57, -56, -30, 108, 61, 24, 106, -56, -92, 99, -59, 107, 25, -110, -57, 80, 79, -92, -107, 90, 54, -73, -40, -39, 78, 109, -57, -62, -17, 6, -25, -29, 37, 90, -24, -27, -61, -69, 44, 121, 107, -72, -57, 108, 32, -69, -21, -41, 126, 91, 118, 11, -91, 50, -11, 116, 126, -96, -39, 110, 105, -52 }, { 48, 108, 123, 50, -50, -58, 33, 14, 59, 102, 17, -18, -119, 4, 10, -29, 36, -56, -31, 43, -71, -48, -14, 87, 119, -119, 40, 104, -44, -76, -24, 2, 48, -96, -7, 16, -119, -3, 108, 78, 125, 88, 61, -53, -3, -16, 20, -83, 74, 124, -47, -17, -15, -21, -23, -119, -47, 105, -4, 115, -20, 77, 57, 88 }, { 33, 101, 79, -35, 32, -119, 20, 120, 34, -80, -41, 90, -22, 93, -20, -45, 9, 24, -46, 80, -55, -9, -24, -78, -124, 27, -120, -36, -51, 59, -38, 7, 113, 125, 68, 109, 24, -121, 111, 37, -71, 100, -111, 78, -43, -14, -76, -44, 64, 103, 16, -28, -44, -103, 74, 81, -118, -74, 47, -77, -65, 8, 42, -100 }, { -63, -96, -95, -111, -85, -98, -85, 42, 87, 29, -62, -57, 57, 48, 9, -39, -110, 63, -103, -114, -48, -11, -92, 105, -26, -79, -11, 78, -118, 14, -39, 1, -115, 74, 70, -41, -119, -68, -39, -60, 64, 31, 25, -111, -16, -20, 61, -22, 17, -13, 57, -110, 24, 61, -104, 21, -72, -69, 56, 116, -117, 93, -1, -123 }, { -18, -70, 12, 112, -111, 10, 22, 31, -120, 26, 53, 14, 10, 69, 51, 45, -50, -127, -22, 95, 54, 17, -8, 54, -115, 36, -79, 12, -79, 82, 4, 1, 92, 59, 23, -13, -85, -87, -110, -58, 84, -31, -48, -105, -101, -92, -9, 28, -109, 77, -47, 100, -48, -83, 106, -102, 70, -95, 94, -1, -99, -15, 21, 99 }, { 109, 123, 54, 40, -120, 32, -118, 49, -52, 0, -103, 103, 101, -9, 32, 78, 124, -56, 88, -19, 101, -32, 70, 67, -41, 85, -103, 1, 1, -105, -51, 10, 4, 51, -26, -19, 39, -43, 63, -41, -101, 80, 106, -66, 125, 47, -117, -120, -93, -120, 99, -113, -17, 61, 102, -2, 72, 9, -124, 123, -128, 78, 43, 96 }, { -22, -63, 20, 65, 5, -89, -123, -61, 14, 34, 83, -113, 34, 85, 26, -21, 1, 16, 88, 55, -92, -111, 14, -31, -37, -67, -8, 85, 39, -112, -33, 8, 28, 16, 107, -29, 1, 3, 100, -53, 2, 81, 52, -94, -14, 36, -123, -82, -6, -118, 104, 75, -99, -82, -100, 7, 30, -66, 0, -59, 108, -54, 31, 20 }, { 0, 13, -74, 28, -54, -12, 45, 36, -24, 55, 43, -110, -72, 117, -110, -56, -72, 85, 79, -89, -92, 65, -67, -34, -24, 38, 67, 42, 84, -94, 91, 13, 100, 89, 20, -95, -76, 2, 116, 34, 67, 52, -80, -101, -22, -32, 51, 32, -76, 44, -93, 11, 42, -69, -12, 7, -52, -55, 122, -10, 48, 21, 92, 110 }, { -115, 19, 115, 28, -56, 118, 111, 26, 18, 123, 111, -96, -115, 120, 105, 62, -123, -124, 101, 51, 3, 18, -89, 127, 48, -27, 39, -78, -118, 5, -2, 6, -105, 17, 123, 26, 25, -62, -37, 49, 117, 3, 10, 97, -7, 54, 121, -90, -51, -49, 11, 104, -66, 11, -6, 57, 5, -64, -8, 59, 82, -126, 26, -113 }, { 16, -53, 94, 99, -46, -29, 64, -89, -59, 116, -21, 53, 14, -77, -71, 95, 22, -121, -51, 125, -14, -96, 95, 95, 32, 96, 79, 41, -39, -128, 79, 0, 5, 6, -115, 104, 103, 77, -92, 93, -109, 58, 96, 97, -22, 116, -62, 11, 30, -122, 14, 28, 69, 124, 63, -119, 19, 80, -36, -116, -76, -58, 36, 87 }, { 109, -82, 33, -119, 17, 109, -109, -16, 98, 108, 111, 5, 98, 1, -15, -32, 22, 46, -65, 117, -78, 119, 35, -35, -3, 41, 23, -97, 55, 69, 58, 9, 20, -113, -121, -13, -41, -48, 22, -73, -1, -44, -73, 3, -10, -122, 19, -103, 10, -26, -128, 62, 34, 55, 54, -43, 35, -30, 115, 64, -80, -20, -25, 67 }, { -16, -74, -116, -128, 52, 96, -75, 17, -22, 72, -43, 22, -95, -16, 32, -72, 98, 46, -4, 83, 34, -58, -108, 18, 17, -58, -123, 53, -108, 116, 18, 2, 7, -94, -126, -45, 72, -69, -65, -89, 64, 31, -78, 78, -115, 106, 67, 55, -123, 104, -128, 36, -23, -90, -14, -87, 78, 19, 18, -128, 39, 73, 35, 120 }, { 20, -30, 15, 111, -82, 39, -108, 57, -80, 98, -19, -27, 100, -18, 47, 77, -41, 95, 80, -113, -128, -88, -76, 115, 65, -53, 83, 115, 7, 2, -104, 3, 120, 115, 14, -116, 33, -15, -120, 22, -56, -8, -69, 5, -75, 94, 124, 12, -126, -48, 51, -105, 22, -66, -93, 16, -63, -74, 32, 114, -54, -3, -47, -126 }, { 56, -101, 55, -1, 64, 4, -64, 95, 31, -15, 72, 46, 67, -9, 68, -43, -55, 28, -63, -17, -16, 65, 11, -91, -91, 32, 88, 41, 60, 67, 105, 8, 58, 102, -79, -5, -113, -113, -67, 82, 50, -26, 116, -78, -103, 107, 102, 23, -74, -47, 115, -50, -35, 63, -80, -32, 72, 117, 47, 68, 86, -20, -35, 8 }, { 21, 27, 20, -59, 117, -102, -42, 22, -10, 121, 41, -59, 115, 15, -43, 54, -79, -62, -16, 58, 116, 15, 88, 108, 114, 67, 3, -30, -99, 78, 103, 11, 49, 63, -4, -110, -27, 41, 70, -57, -69, -18, 70, 30, -21, 66, -104, -27, 3, 53, 50, 100, -33, 54, -3, -78, 92, 85, -78, 54, 19, 32, 95, 9 }, { -93, 65, -64, -79, 82, 85, -34, -90, 122, -29, -40, 3, -80, -40, 32, 26, 102, -73, 17, 53, -93, -29, 122, 86, 107, -100, 50, 56, -28, 124, 90, 14, 93, -88, 97, 101, -85, -50, 46, -109, -88, -127, -112, 63, -89, 24, -34, -9, -116, -59, -87, -86, -12, 111, -111, 87, -87, -13, -73, -124, -47, 7, 1, 9 }, { 60, -99, -77, -20, 112, -75, -34, 100, -4, -96, 81, 71, -116, -62, 38, -68, 105, 7, -126, 21, -125, -25, -56, -11, -59, 95, 117, 108, 32, -38, -65, 13, 46, 65, -46, -89, 0, 120, 5, 23, 40, 110, 114, 79, 111, -70, 8, 16, -49, -52, -82, -18, 108, -43, 81, 96, 72, -65, 70, 7, -37, 58, 46, -14 }, { -95, -32, 85, 78, 74, -53, 93, -102, -26, -110, 86, 1, -93, -50, -23, -108, -37, 97, 19, 103, 94, -65, -127, -21, 60, 98, -51, -118, 82, -31, 27, 7, -112, -45, 79, 95, -20, 90, -4, -40, 117, 100, -6, 19, -47, 53, 53, 48, 105, 91, -70, -34, -5, -87, -57, -103, -112, -108, -40, 87, -25, 13, -76, -116 }, { 44, -122, -70, 125, -60, -32, 38, 69, -77, -103, 49, -124, -4, 75, -41, -84, 68, 74, 118, 15, -13, 115, 117, -78, 42, 89, 0, -20, -12, -58, -97, 10, -48, 95, 81, 101, 23, -67, -23, 74, -79, 21, 97, 123, 103, 101, -50, -115, 116, 112, 51, 50, -124, 27, 76, 40, 74, 10, 65, -49, 102, 95, 5, 35 }, { -6, 57, 71, 5, -61, -100, -21, -9, 47, -60, 59, 108, -75, 105, 56, 41, -119, 31, 37, 27, -86, 120, -125, -108, 121, 104, -21, -70, -57, -104, 2, 11, 118, 104, 68, 6, 7, -90, -70, -61, -16, 77, -8, 88, 31, -26, 35, -44, 8, 50, 51, -88, -62, -103, 54, -41, -2, 117, 98, -34, 49, -123, 83, -58 }, { 54, 21, -36, 126, -50, -72, 82, -5, -122, -116, 72, -19, -18, -68, -71, -27, 97, -22, 53, -94, 47, -6, 15, -92, -55, 127, 13, 13, -69, 81, -82, 8, -50, 10, 84, 110, -87, -44, 61, -78, -65, 84, -32, 48, -8, -105, 35, 116, -68, -116, -6, 75, -77, 120, -95, 74, 73, 105, 39, -87, 98, -53, 47, 10 }, { -113, 116, 37, -1, 95, -89, -93, 113, 36, -70, -57, -99, 94, 52, -81, -118, 98, 58, -36, 73, 82, -67, -80, 46, 83, -127, -8, 73, 66, -27, 43, 7, 108, 32, 73, 1, -56, -108, 41, -98, -15, 49, 1, 107, 65, 44, -68, 126, -28, -53, 120, -114, 126, -79, -14, -105, -33, 53, 5, -119, 67, 52, 35, -29 }, { 98, 23, 23, 83, 78, -89, 13, 55, -83, 97, -30, -67, 99, 24, 47, -4, -117, -34, -79, -97, 95, 74, 4, 21, 66, -26, 15, 80, 60, -25, -118, 14, 36, -55, -41, -124, 90, -1, 84, 52, 31, 88, 83, 121, -47, -59, -10, 17, 51, -83, 23, 108, 19, 104, 32, 29, -66, 24, 21, 110, 104, -71, -23, -103 }, { 12, -23, 60, 35, 6, -52, -67, 96, 15, -128, -47, -15, 40, 3, 54, -81, 3, 94, 3, -98, -94, -13, -74, -101, 40, -92, 90, -64, -98, 68, -25, 2, -62, -43, 112, 32, -78, -123, 26, -80, 126, 120, -88, -92, 126, -128, 73, -43, 87, -119, 81, 111, 95, -56, -128, -14, 51, -40, -42, 102, 46, 106, 6, 6 }, { -38, -120, -11, -114, -7, -105, -98, 74, 114, 49, 64, -100, 4, 40, 110, -21, 25, 6, -92, -40, -61, 48, 94, -116, -71, -87, 75, -31, 13, -119, 1, 5, 33, -69, -16, -125, -79, -46, -36, 3, 40, 1, -88, -118, -107, 95, -23, -107, -49, 44, -39, 2, 108, -23, 39, 50, -51, -59, -4, -42, -10, 60, 10, -103 }, { 67, -53, 55, -32, -117, 3, 94, 52, -115, -127, -109, 116, -121, -27, -115, -23, 98, 90, -2, 48, -54, -76, 108, -56, 99, 30, -35, -18, -59, 25, -122, 3, 43, -13, -109, 34, -10, 123, 117, 113, -112, -85, -119, -62, -78, -114, -96, 101, 72, -98, 28, 89, -98, -121, 20, 115, 89, -20, 94, -55, 124, 27, -76, 94 }, { 15, -101, 98, -21, 8, 5, -114, -64, 74, 123, 99, 28, 125, -33, 22, 23, -2, -56, 13, 91, 27, -105, -113, 19, 60, -7, -67, 107, 70, 103, -107, 13, -38, -108, -77, -29, 2, 9, -12, 21, 12, 65, 108, -16, 69, 77, 96, -54, 55, -78, -7, 41, -48, 124, -12, 64, 113, -45, -21, -119, -113, 88, -116, 113 }, { -17, 77, 10, 84, -57, -12, 101, 21, -91, 92, 17, -32, -26, 77, 70, 46, 81, -55, 40, 44, 118, -35, -97, 47, 5, 125, 41, -127, -72, 66, -18, 2, 115, -13, -74, 126, 86, 80, 11, -122, -29, -68, 113, 54, -117, 107, -75, -107, -54, 72, -44, 98, -111, -33, -56, -40, 93, -47, 84, -43, -45, 86, 65, -84 }, { -126, 60, -56, 121, 31, -124, -109, 100, -118, -29, 106, 94, 5, 27, 13, -79, 91, -111, -38, -42, 18, 61, -100, 118, -18, -4, -60, 121, 46, -22, 6, 4, -37, -20, 124, -43, 51, -57, -49, -44, -24, -38, 81, 60, -14, -97, -109, -11, -5, -85, 75, -17, -124, -96, -53, 52, 64, 100, -118, -120, 6, 60, 76, -110 }, { -12, -40, 115, -41, 68, 85, 20, 91, -44, -5, 73, -105, -81, 32, 116, 32, -28, 69, 88, -54, 29, -53, -51, -83, 54, 93, -102, -102, -23, 7, 110, 15, 34, 122, 84, 52, -121, 37, -103, -91, 37, -77, -101, 64, -18, 63, -27, -75, -112, -11, 1, -69, -25, -123, -99, -31, 116, 11, 4, -42, -124, 98, -2, 53 }, { -128, -69, -16, -33, -8, -112, 39, -57, 113, -76, -29, -37, 4, 121, -63, 12, -54, -66, -121, 13, -4, -44, 50, 27, 103, 101, 44, -115, 12, -4, -8, 10, 53, 108, 90, -47, 46, -113, 5, -3, -111, 8, -66, -73, 57, 72, 90, -33, 47, 99, 50, -55, 53, -4, 96, 87, 57, 26, 53, -45, -83, 39, -17, 45 }, { -121, 125, 60, -9, -79, -128, -19, 113, 54, 77, -23, -89, 105, -5, 47, 114, -120, -88, 31, 25, -96, -75, -6, 76, 9, -83, 75, -109, -126, -47, -6, 2, -59, 64, 3, 74, 100, 110, -96, 66, -3, 10, -124, -6, 8, 50, 109, 14, -109, 79, 73, 77, 67, 63, -50, 10, 86, -63, -125, -86, 35, -26, 7, 83 }, { 36, 31, -77, 126, 106, 97, 63, 81, -37, -126, 69, -127, -22, -69, 104, -111, 93, -49, 77, -3, -38, -112, 47, -55, -23, -68, -8, 78, -127, -28, -59, 10, 22, -61, -127, -13, -72, -14, -87, 14, 61, 76, -89, 81, -97, -97, -105, 94, -93, -9, -3, -104, -83, 59, 104, 121, -30, 106, -2, 62, -51, -72, -63, 55 }, { 81, -88, -8, -96, -31, 118, -23, -38, -94, 80, 35, -20, -93, -102, 124, 93, 0, 15, 36, -127, -41, -19, 6, -124, 94, -49, 44, 26, -69, 43, -58, 9, -18, -3, -2, 60, -122, -30, -47, 124, 71, 47, -74, -68, 4, -101, -16, 77, -120, -15, 45, -12, 68, -77, -74, 63, -113, 44, -71, 56, 122, -59, 53, -44 }, { 122, 30, 27, -79, 32, 115, -104, -28, -53, 109, 120, 121, -115, -65, -87, 101, 23, 10, 122, 101, 29, 32, 56, 63, -23, -48, -51, 51, 16, -124, -41, 6, -71, 49, -20, 26, -57, 65, 49, 45, 7, 49, -126, 54, -122, -43, 1, -5, 111, 117, 104, 117, 126, 114, -77, 66, -127, -50, 69, 14, 70, 73, 60, 112 }, { 104, -117, 105, -118, 35, 16, -16, 105, 27, -87, -43, -59, -13, -23, 5, 8, -112, -28, 18, -1, 48, 94, -82, 55, 32, 16, 59, -117, 108, -89, 101, 9, -35, 58, 70, 62, 65, 91, 14, -43, -104, 97, 1, -72, 16, -24, 79, 79, -85, -51, -79, -55, -128, 23, 109, -95, 17, 92, -38, 109, 65, -50, 46, -114 }, { 44, -3, 102, -60, -85, 66, 121, -119, 9, 82, -47, -117, 67, -28, 108, 57, -47, -52, -24, -82, 65, -13, 85, 107, -21, 16, -24, -85, 102, -92, 73, 5, 7, 21, 41, 47, -118, 72, 43, 51, -5, -64, 100, -34, -25, 53, -45, -115, 30, -72, -114, 126, 66, 60, -24, -67, 44, 48, 22, 117, -10, -33, -89, -108 }, { -7, 71, -93, -66, 3, 30, -124, -116, -48, -76, -7, -62, 125, -122, -60, -104, -30, 71, 36, -110, 34, -126, 31, 10, 108, 102, -53, 56, 104, -56, -48, 12, 25, 21, 19, -90, 45, -122, -73, -112, 97, 96, 115, 71, 127, -7, -46, 84, -24, 102, -104, -96, 28, 8, 37, -84, -13, -65, -6, 61, -85, -117, -30, 70 }, { -112, 39, -39, -24, 127, -115, 68, -1, -111, -43, 101, 20, -12, 39, -70, 67, -50, 68, 105, 69, -91, -106, 91, 4, -52, 75, 64, -121, 46, -117, 31, 10, -125, 77, 51, -3, -93, 58, 79, 121, 126, -29, 56, -101, 1, -28, 49, 16, -80, 92, -62, 83, 33, 17, 106, 89, -9, 60, 79, 38, -74, -48, 119, 24 }, { 105, -118, 34, 52, 111, 30, 38, -73, 125, -116, 90, 69, 2, 126, -34, -25, -41, -67, -23, -105, -12, -75, 10, 69, -51, -95, -101, 92, -80, -73, -120, 2, 71, 46, 11, -85, -18, 125, 81, 117, 33, -89, -42, 118, 51, 60, 89, 110, 97, -118, -111, -36, 75, 112, -4, -8, -36, -49, -55, 35, 92, 70, -37, 36 }, { 71, 4, -113, 13, -48, 29, -56, 82, 115, -38, -20, -79, -8, 126, -111, 5, -12, -56, -107, 98, 111, 19, 127, -10, -42, 24, -38, -123, 59, 51, -64, 3, 47, -1, -83, -127, -58, 86, 33, -76, 5, 71, -80, -50, -62, 116, 75, 20, -126, 23, -31, -21, 24, -83, -19, 114, -17, 1, 110, -70, -119, 126, 82, -83 }, { -77, -69, -45, -78, -78, 69, 35, 85, 84, 25, -66, -25, 53, -38, -2, 125, -38, 103, 88, 31, -9, -43, 15, -93, 69, -22, -13, -20, 73, 3, -100, 7, 26, -18, 123, -14, -78, 113, 79, -57, -109, -118, 105, -104, 75, -88, -24, -109, 73, -126, 9, 55, 98, -120, 93, 114, 74, 0, -86, -68, 47, 29, 75, 67 }, { -104, 11, -85, 16, -124, -91, 66, -91, 18, -67, -122, -57, -114, 88, 79, 11, -60, -119, 89, 64, 57, 120, -11, 8, 52, -18, -67, -127, 26, -19, -69, 2, -82, -56, 11, -90, -104, 110, -10, -68, 87, 21, 28, 87, -5, -74, -21, -84, 120, 70, -17, 102, 72, -116, -69, 108, -86, -79, -74, 115, -78, -67, 6, 45 }, { -6, -101, -17, 38, -25, -7, -93, 112, 13, -33, 121, 71, -79, -122, -95, 22, 47, -51, 16, 84, 55, -39, -26, 37, -36, -18, 11, 119, 106, -57, 42, 8, -1, 23, 7, -63, -9, -50, 30, 35, -125, 83, 9, -60, -94, -15, -76, 120, 18, -103, -70, 95, 26, 48, -103, -95, 10, 113, 66, 54, -96, -4, 37, 111 }, { -124, -53, 43, -59, -73, 99, 71, -36, -31, 61, -25, -14, -71, 48, 17, 10, -26, -21, -22, 104, 64, -128, 27, -40, 111, -70, -90, 91, -81, -88, -10, 11, -62, 127, -124, -2, -67, -69, 65, 73, 40, 82, 112, -112, 100, -26, 30, 86, 30, 1, -105, 45, 103, -47, -124, 58, 105, 24, 20, 108, -101, 84, -34, 80 }, { 28, -1, 84, 111, 43, 109, 57, -23, 52, -95, 110, -50, 77, 15, 80, 85, 125, -117, -10, 8, 59, -58, 18, 97, -58, 45, 92, -3, 56, 24, -117, 9, -73, -9, 48, -99, 50, -24, -3, -41, -43, 48, -77, -8, -89, -42, 126, 73, 28, -65, -108, 54, 6, 34, 32, 2, -73, -123, -106, -52, -73, -106, -112, 109 }, { 73, -76, -7, 49, 67, -34, 124, 80, 111, -91, -22, -121, -74, 42, -4, -18, 84, -3, 38, 126, 31, 54, -120, 65, -122, -14, -38, -80, -124, 90, 37, 1, 51, 123, 69, 48, 109, -112, -63, 27, 67, -127, 29, 79, -26, 99, -24, -100, 51, 103, -105, 13, 85, 74, 12, -37, 43, 80, -113, 6, 70, -107, -5, -80 }, { 110, -54, 109, 21, -124, 98, 90, -26, 69, -44, 17, 117, 78, -91, -7, -18, -81, -43, 20, 80, 48, -109, 117, 125, -67, 19, -15, 69, -28, 47, 15, 4, 34, -54, 51, -128, 18, 61, -77, -122, 100, -58, -118, -36, 5, 32, 43, 15, 60, -55, 120, 123, -77, -76, -121, 77, 93, 16, -73, 54, 46, -83, -39, 125 }, { 115, -15, -42, 111, -124, 52, 29, -124, -10, -23, 41, -128, 65, -60, -121, 6, -42, 14, 98, -80, 80, -46, -38, 64, 16, 84, -50, 47, -97, 11, -88, 12, 68, -127, -92, 87, -22, 54, -49, 33, -4, -68, 21, -7, -45, 84, 107, 57, 8, -106, 0, -87, -104, 93, -43, -98, -92, -72, 110, -14, -66, 119, 14, -68 }, { -19, 7, 7, 66, -94, 18, 36, 8, -58, -31, 21, -113, -124, -5, -12, 105, 40, -62, 57, -56, 25, 117, 49, 17, -33, 49, 105, 113, -26, 78, 97, 2, -22, -84, 49, 67, -6, 33, 89, 28, 30, 12, -3, -23, -45, 7, -4, -39, -20, 25, -91, 55, 53, 21, -94, 17, -54, 109, 125, 124, 122, 117, -125, 60 }, { -28, -104, -46, -22, 71, -79, 100, 48, -90, -57, -30, -23, -24, 1, 2, -31, 85, -6, -113, -116, 105, -31, -109, 106, 1, 78, -3, 103, -6, 100, -44, 15, -100, 97, 59, -42, 22, 83, 113, -118, 112, -57, 80, -45, -86, 72, 77, -26, -106, 50, 28, -24, 41, 22, -73, 108, 18, -93, 30, 8, -11, -16, 124, 106 }, { 16, -119, -109, 115, 67, 36, 28, 74, 101, -58, -82, 91, 4, -97, 111, -77, -37, -125, 126, 3, 10, -99, -115, 91, -66, -83, -81, 10, 7, 92, 26, 6, -45, 66, -26, 118, -77, 13, -91, 20, -18, -33, -103, 43, 75, -100, -5, -64, 117, 30, 5, -100, -90, 13, 18, -52, 26, 24, -10, 24, -31, 53, 88, 112 }, { 7, -90, 46, 109, -42, 108, -84, 124, -28, -63, 34, -19, -76, 88, -121, 23, 54, -73, -15, -52, 84, -119, 64, 20, 92, -91, -58, -121, -117, -90, -102, 1, 49, 21, 3, -85, -3, 38, 117, 73, -38, -71, -37, 40, -2, -50, -47, -46, 75, -105, 125, 126, -13, 68, 50, -81, -43, -93, 85, -79, 52, 98, 118, 50 }, { -104, 65, -61, 12, 68, 106, 37, -64, 40, -114, 61, 73, 74, 61, -113, -79, 57, 47, -57, -21, -68, -62, 23, -18, 93, -7, -55, -88, -106, 104, -126, 5, 53, 97, 100, -67, -112, -88, 41, 24, 95, 15, 25, -67, 79, -69, 53, 21, -128, -101, 73, 17, 7, -98, 5, -2, 33, -113, 99, -72, 125, 7, 18, -105 }, { -17, 28, 79, 34, 110, 86, 43, 27, -114, -112, -126, -98, -121, 126, -21, 111, 58, -114, -123, 75, 117, -116, 7, 107, 90, 80, -75, -121, 116, -11, -76, 0, -117, -52, 76, -116, 115, -117, 61, -7, 55, -34, 38, 101, 86, -19, -36, -92, -94, 61, 88, -128, -121, -103, 84, 19, -83, -102, 122, -111, 62, 112, 20, 3 }, { -127, -90, 28, -77, -48, -56, -10, 84, -41, 59, -115, 68, -74, -104, -119, -49, -37, -90, -57, 66, 108, 110, -62, -107, 88, 90, 29, -65, 74, -38, 95, 8, 120, 88, 96, -65, -109, 68, -63, -4, -16, 90, 7, 39, -56, -110, -100, 86, -39, -53, -89, -35, 127, -42, -48, -36, 53, -66, 109, -51, 51, -23, -12, 73 }, { -12, 78, 81, 30, 124, 22, 56, -112, 58, -99, 30, -98, 103, 66, 89, 92, -52, -20, 26, 82, -92, -18, 96, 7, 38, 21, -9, -25, -17, 4, 43, 15, 111, 103, -48, -50, -83, 52, 59, 103, 102, 83, -105, 87, 20, -120, 35, -7, -39, -24, 29, -39, -35, -87, 88, 120, 126, 19, 108, 34, -59, -20, 86, 47 }, { 19, -70, 36, 55, -42, -49, 33, 100, 105, -5, 89, 43, 3, -85, 60, -96, 43, -46, 86, -33, 120, -123, -99, -100, -34, 48, 82, -37, 34, 78, 127, 12, -39, -76, -26, 117, 74, -60, -68, -2, -37, -56, -6, 94, -27, 81, 32, -96, -19, -32, -77, 22, -56, -49, -38, -60, 45, -69, 40, 106, -106, -34, 101, -75 }, { 57, -92, -44, 8, -79, -88, -82, 58, -116, 93, 103, -127, 87, -121, -28, 31, -108, -14, -23, 38, 57, -83, -33, -110, 24, 6, 68, 124, -89, -35, -127, 5, -118, -78, -127, -35, 112, -34, 30, 24, -70, -71, 126, 39, -124, 122, -35, -97, -18, 25, 119, 79, 119, -65, 59, -20, -84, 120, -47, 4, -106, -125, -38, -113 }, { 18, -93, 34, -80, -43, 127, 57, -118, 24, -119, 25, 71, 59, -29, -108, -99, -122, 58, 44, 0, 42, -111, 25, 94, -36, 41, -64, -53, -78, -119, 85, 7, -45, -70, 81, -84, 71, -61, -68, -79, 112, 117, 19, 18, 70, 95, 108, -58, 48, 116, -89, 43, 66, 55, 37, -37, -60, 104, 47, -19, -56, 97, 73, 26 }, { 78, 4, -111, -36, 120, 111, -64, 46, 99, 125, -5, 97, -126, -21, 60, -78, -33, 89, 25, -60, 0, -49, 59, -118, 18, 3, -60, 30, 105, -92, -101, 15, 63, 50, 25, 2, -116, 78, -5, -25, -59, 74, -116, 64, -55, -121, 1, 69, 51, -119, 43, -6, -81, 14, 5, 84, -67, -73, 67, 24, 82, -37, 109, -93 }, { -44, -30, -64, -68, -21, 74, 124, 122, 114, -89, -91, -51, 89, 32, 96, -1, -101, -112, -94, 98, -24, -31, -50, 100, -72, 56, 24, 30, 105, 115, 15, 3, -67, 107, -18, 111, -38, -93, -11, 24, 36, 73, -23, 108, 14, -41, -65, 32, 51, 22, 95, 41, 85, -121, -35, -107, 0, 105, -112, 59, 48, -22, -84, 46 }, { 4, 38, 54, -84, -78, 24, -48, 8, -117, 78, -95, 24, 25, -32, -61, 26, -97, -74, 46, -120, -125, 27, 73, 107, -17, -21, -6, -52, 47, -68, 66, 5, -62, -12, -102, -127, 48, -69, -91, -81, -33, -13, -9, -12, -44, -73, 40, -58, 120, -120, 108, 101, 18, -14, -17, -93, 113, 49, 76, -4, -113, -91, -93, -52 }, { 28, -48, 70, -35, 123, -31, 16, -52, 72, 84, -51, 78, 104, 59, -102, -112, 29, 28, 25, 66, 12, 75, 26, -85, 56, -12, -4, -92, 49, 86, -27, 12, 44, -63, 108, 82, -76, -97, -41, 95, -48, -95, -115, 1, 64, -49, -97, 90, 65, 46, -114, -127, -92, 79, 100, 49, 116, -58, -106, 9, 117, -7, -91, 96 }, { 58, 26, 18, 76, 127, -77, -58, -87, -116, -44, 60, -32, -4, -76, -124, 4, -60, 82, -5, -100, -95, 18, 2, -53, -50, -96, -126, 105, 93, 19, 74, 13, 87, 125, -72, -10, 42, 14, 91, 44, 78, 52, 60, -59, -27, -37, -57, 17, -85, 31, -46, 113, 100, -117, 15, 108, -42, 12, 47, 63, 1, 11, -122, -3 } };
        for (int i3 = 0; i3 < ???.length; ++i3)
        {
          localObject4 = new Nxt.Transaction(0, 0, 0, 0, new byte[] { 18, 89, -20, 33, -45, 26, 48, -119, -115, 124, -47, 96, -97, -128, -39, 102, -117, 71, 120, -29, -39, 126, -108, 16, 68, -77, -97, 12, 68, -46, -27, 27 }, ???[i3], arrayOfInt[i3], 0, 0L, arrayOfByte[i3]);
          transactions.put(Long.valueOf(((Nxt.Transaction)localObject4).getId()), localObject4);
        }
        localObject4 = transactions.values().iterator();
        while (((Iterator)localObject4).hasNext())
        {
          localObject3 = (Nxt.Transaction)((Iterator)localObject4).next();
          ((Nxt.Transaction)localObject3).index = (++transactionCounter);
          ((Nxt.Transaction)localObject3).block = 2680262203532249785L;
        }
        Nxt.Transaction.saveTransactions("transactions.nxt");
      }
      try
      {
        logMessage("Loading blocks...");
        Nxt.Block.loadBlocks("blocks.nxt");
        logMessage("...Done");
      }
      catch (FileNotFoundException localFileNotFoundException2)
      {
        blocks = new HashMap();
        ??? = new Nxt.Block(-1, 0, 0L, transactions.size(), 1000000000, 0, transactions.size() * 128, null, new byte[] { 18, 89, -20, 33, -45, 26, 48, -119, -115, 124, -47, 96, -97, -128, -39, 102, -117, 71, 120, -29, -39, 126, -108, 16, 68, -77, -97, 12, 68, -46, -27, 27 }, new byte[64], new byte[] { 105, -44, 38, -60, -104, -73, 10, -58, -47, 103, -127, -128, 53, 101, 39, -63, -2, -32, 48, -83, 115, 47, -65, 118, 114, -62, 38, 109, 22, 106, 76, 8, -49, -113, -34, -76, 82, 79, -47, -76, -106, -69, -54, -85, 3, -6, 110, 103, 118, 15, 109, -92, 82, 37, 20, 2, 36, -112, 21, 72, 108, 72, 114, 17 });
        ((Nxt.Block)???).index = (++blockCounter);
        blocks.put(Long.valueOf(2680262203532249785L), ???);
        ((Nxt.Block)???).transactions = new long[((Nxt.Block)???).numberOfTransactions];
        int i2 = 0;
        localObject4 = transactions.keySet().iterator();
        while (((Iterator)localObject4).hasNext())
        {
          long l2 = ((Long)((Iterator)localObject4).next()).longValue();
          ???.transactions[(i2++)] = l2;
        }
        Arrays.sort(((Nxt.Block)???).transactions);
        MessageDigest localMessageDigest = MessageDigest.getInstance("SHA-256");
        for (i2 = 0; i2 < ((Nxt.Block)???).numberOfTransactions; ++i2)
          localMessageDigest.update(((Nxt.Transaction)transactions.get(Long.valueOf(???.transactions[i2]))).getBytes());
        ((Nxt.Block)???).payloadHash = localMessageDigest.digest();
        ((Nxt.Block)???).baseTarget = 153722867L;
        lastBlock = 2680262203532249785L;
        ((Nxt.Block)???).cumulativeDifficulty = BigInteger.ZERO;
        Nxt.Block.saveBlocks("blocks.nxt", false);
      }
      logMessage("Scanning blockchain...");
      ??? = blocks;
      blocks = new HashMap();
      lastBlock = 2680262203532249785L;
      long l1 = 2680262203532249785L;
      do
      {
        localObject3 = (Nxt.Block)((HashMap)???).get(Long.valueOf(l1));
        long l3 = ((Nxt.Block)localObject3).nextBlock;
        ((Nxt.Block)localObject3).analyze();
        l1 = l3;
      }
      while (l1 != 0L);
      logMessage("...Done");
      scheduledThreadPool.scheduleWithFixedDelay(new Runnable()
      {
        public void run()
        {
          try
          {
            if (Nxt.Peer.getNumberOfConnectedPublicPeers() >= Nxt.maxNumberOfConnectedPublicPeers)
              return;
            Nxt.Peer localPeer = Nxt.Peer.getAnyPeer((ThreadLocalRandom.current().nextInt(2) == 0) ? 0 : 2, false);
            if (localPeer == null)
              return;
            localPeer.connect();
          }
          catch (Exception localException)
          {
          }
        }
      }
      , 0L, 1L, TimeUnit.SECONDS);
      scheduledThreadPool.scheduleWithFixedDelay(new Runnable()
      {
        public void run()
        {
          try
          {
            long l = System.currentTimeMillis();
            Collection localCollection;
            synchronized (Nxt.peers)
            {
              localCollection = ((HashMap)Nxt.peers.clone()).values();
            }
            Iterator localIterator = localCollection.iterator();
            while (localIterator.hasNext())
            {
              ??? = (Nxt.Peer)localIterator.next();
              if ((((Nxt.Peer)???).blacklistingTime <= 0L) || (((Nxt.Peer)???).blacklistingTime + Nxt.blacklistingPeriod > l))
                continue;
              ((Nxt.Peer)???).removeBlacklistedStatus();
            }
          }
          catch (Exception localException)
          {
          }
        }
      }
      , 0L, 1L, TimeUnit.SECONDS);
      scheduledThreadPool.scheduleWithFixedDelay(new Runnable()
      {
        public void run()
        {
          try
          {
            Nxt.Peer localPeer = Nxt.Peer.getAnyPeer(1, true);
            if (localPeer == null)
              return;
            JSONObject localJSONObject1 = new JSONObject();
            localJSONObject1.put("requestType", "getPeers");
            JSONObject localJSONObject2 = localPeer.send(localJSONObject1);
            if (localJSONObject2 == null)
              return;
            JSONArray localJSONArray = (JSONArray)localJSONObject2.get("peers");
            for (int i = 0; i < localJSONArray.size(); ++i)
            {
              String str = ((String)localJSONArray.get(i)).trim();
              if (str.length() <= 0)
                continue;
              Nxt.Peer.addPeer(str, str);
            }
          }
          catch (Exception localException)
          {
          }
        }
      }
      , 0L, 5L, TimeUnit.SECONDS);
      scheduledThreadPool.scheduleWithFixedDelay(new Runnable()
      {
        public void run()
        {
          try
          {
            Nxt.Peer localPeer = Nxt.Peer.getAnyPeer(1, true);
            if (localPeer == null)
              return;
            JSONObject localJSONObject1 = new JSONObject();
            localJSONObject1.put("requestType", "getUnconfirmedTransactions");
            JSONObject localJSONObject2 = localPeer.send(localJSONObject1);
            if (localJSONObject2 == null)
              return;
            Nxt.Transaction.processTransactions(localJSONObject2, "unconfirmedTransactions");
          }
          catch (Exception localException)
          {
          }
        }
      }
      , 0L, 5L, TimeUnit.SECONDS);
      scheduledThreadPool.scheduleWithFixedDelay(new Runnable()
      {
        public void run()
        {
          try
          {
            int i = Nxt.getEpochTime(System.currentTimeMillis());
            synchronized (Nxt.transactions)
            {
              JSONArray localJSONArray = new JSONArray();
              Iterator localIterator = Nxt.unconfirmedTransactions.values().iterator();
              Object localObject1;
              Object localObject2;
              while (localIterator.hasNext())
              {
                localObject1 = (Nxt.Transaction)localIterator.next();
                if ((((Nxt.Transaction)localObject1).timestamp + ((Nxt.Transaction)localObject1).deadline * 60 >= i) && (((Nxt.Transaction)localObject1).validateAttachment()))
                  continue;
                localIterator.remove();
                localObject2 = (Nxt.Account)Nxt.accounts.get(Long.valueOf(Nxt.Account.getId(((Nxt.Transaction)localObject1).senderPublicKey)));
                synchronized (localObject2)
                {
                  ((Nxt.Account)localObject2).setUnconfirmedBalance(((Nxt.Account)localObject2).unconfirmedBalance + (((Nxt.Transaction)localObject1).amount + ((Nxt.Transaction)localObject1).fee) * 100L);
                }
                ??? = new JSONObject();
                ((JSONObject)???).put("index", Integer.valueOf(((Nxt.Transaction)localObject1).index));
                localJSONArray.add(???);
              }
              if (localJSONArray.size() > 0)
              {
                localObject1 = new JSONObject();
                ((JSONObject)localObject1).put("response", "processNewData");
                ((JSONObject)localObject1).put("removedUnconfirmedTransactions", localJSONArray);
                ??? = Nxt.users.values().iterator();
                while (((Iterator)???).hasNext())
                {
                  localObject2 = (Nxt.User)((Iterator)???).next();
                  ((Nxt.User)localObject2).send((JSONObject)localObject1);
                }
              }
            }
          }
          catch (Exception localException)
          {
          }
        }
      }
      , 0L, 1L, TimeUnit.SECONDS);
      scheduledThreadPool.scheduleWithFixedDelay(new Runnable()
      {
        public void run()
        {
          try
          {
            Nxt.Peer localPeer = Nxt.Peer.getAnyPeer(1, true);
            if (localPeer == null)
              return;
            Nxt.lastBlockchainFeeder = localPeer;
            JSONObject localJSONObject1 = new JSONObject();
            localJSONObject1.put("requestType", "getCumulativeDifficulty");
            JSONObject localJSONObject2 = localPeer.send(localJSONObject1);
            if (localJSONObject2 == null)
              return;
            BigInteger localBigInteger1 = Nxt.Block.getLastBlock().cumulativeDifficulty;
            BigInteger localBigInteger2 = new BigInteger((String)localJSONObject2.get("cumulativeDifficulty"));
            if (localBigInteger2.compareTo(localBigInteger1) <= 0)
              return;
            localJSONObject1 = new JSONObject();
            localJSONObject1.put("requestType", "getMilestoneBlockIds");
            localJSONObject2 = localPeer.send(localJSONObject1);
            if (localJSONObject2 == null)
              return;
            long l1 = 2680262203532249785L;
            JSONArray localJSONArray1 = (JSONArray)localJSONObject2.get("milestoneBlockIds");
            for (int i = 0; i < localJSONArray1.size(); ++i)
            {
              long l2 = new BigInteger((String)localJSONArray1.get(i)).longValue();
              Nxt.Block localBlock = (Nxt.Block)Nxt.blocks.get(Long.valueOf(l2));
              if (localBlock == null)
                continue;
              l1 = l2;
              break;
            }
            int j;
            do
            {
              localJSONObject1 = new JSONObject();
              localJSONObject1.put("requestType", "getNextBlockIds");
              localJSONObject1.put("blockId", Nxt.convert(l1));
              localJSONObject2 = localPeer.send(localJSONObject1);
              if (localJSONObject2 == null)
                return;
              JSONArray localJSONArray2 = (JSONArray)localJSONObject2.get("nextBlockIds");
              j = localJSONArray2.size();
              if (j == 0)
                return;
              for (i = 0; i < j; ++i)
              {
                long l4 = new BigInteger((String)localJSONArray2.get(i)).longValue();
                if (Nxt.blocks.get(Long.valueOf(l4)) == null)
                  break;
                l1 = l4;
              }
            }
            while (i == j);
            if (Nxt.Block.getLastBlock().height - ((Nxt.Block)Nxt.blocks.get(Long.valueOf(l1))).height >= 720)
              return;
            long l3 = l1;
            LinkedList localLinkedList = new LinkedList();
            HashMap localHashMap = new HashMap();
            Object localObject1;
            Object localObject2;
            int k;
            while (true)
            {
              localJSONObject1 = new JSONObject();
              localJSONObject1.put("requestType", "getNextBlocks");
              localJSONObject1.put("blockId", Nxt.convert(l3));
              localJSONObject2 = localPeer.send(localJSONObject1);
              if (localJSONObject2 == null)
                break;
              JSONArray localJSONArray3 = (JSONArray)localJSONObject2.get("nextBlocks");
              j = localJSONArray3.size();
              if (j == 0)
                break;
              for (i = 0; i < j; ++i)
              {
                localObject1 = (JSONObject)localJSONArray3.get(i);
                localObject2 = Nxt.Block.getBlock((JSONObject)localObject1);
                l3 = ((Nxt.Block)localObject2).getId();
                synchronized (Nxt.blocks)
                {
                  k = 0;
                  Object localObject3;
                  if (((Nxt.Block)localObject2).previousBlock == Nxt.lastBlock)
                  {
                    localObject3 = ByteBuffer.allocate(224 + ((Nxt.Block)localObject2).payloadLength);
                    ((ByteBuffer)localObject3).order(ByteOrder.LITTLE_ENDIAN);
                    ((ByteBuffer)localObject3).put(((Nxt.Block)localObject2).getBytes());
                    JSONArray localJSONArray4 = (JSONArray)((JSONObject)localObject1).get("transactions");
                    for (int i1 = 0; i1 < localJSONArray4.size(); ++i1)
                      ((ByteBuffer)localObject3).put(Nxt.Transaction.getTransaction((JSONObject)localJSONArray4.get(i1)).getBytes());
                    if (Nxt.Block.pushBlock((ByteBuffer)localObject3, false))
                    {
                      k = 1;
                    }
                    else
                    {
                      localPeer.blacklist();
                      return;
                    }
                  }
                  if ((k == 0) && (Nxt.blocks.get(Long.valueOf(((Nxt.Block)localObject2).getId())) == null))
                  {
                    localLinkedList.add(localObject2);
                    ((Nxt.Block)localObject2).transactions = new long[((Nxt.Block)localObject2).numberOfTransactions];
                    localObject3 = (JSONArray)((JSONObject)localObject1).get("transactions");
                    for (int l = 0; l < ((Nxt.Block)localObject2).numberOfTransactions; ++l)
                    {
                      Nxt.Transaction localTransaction = Nxt.Transaction.getTransaction((JSONObject)((JSONArray)localObject3).get(l));
                      localObject2.transactions[l] = localTransaction.getId();
                      localHashMap.put(Long.valueOf(localObject2.transactions[l]), localTransaction);
                    }
                  }
                }
              }
            }
            if ((!localLinkedList.isEmpty()) && (Nxt.Block.getLastBlock().height - ((Nxt.Block)Nxt.blocks.get(Long.valueOf(l1))).height < 720))
              synchronized (Nxt.blocks)
              {
                Nxt.Block.saveBlocks("blocks.nxt.bak", true);
                Nxt.Transaction.saveTransactions("transactions.nxt.bak");
                localBigInteger1 = Nxt.Block.getLastBlock().cumulativeDifficulty;
                while ((Nxt.lastBlock != l1) && (Nxt.Block.popLastBlock()));
                if (Nxt.lastBlock == l1)
                {
                  localObject2 = localLinkedList.iterator();
                  while (((Iterator)localObject2).hasNext())
                  {
                    localObject1 = (Nxt.Block)((Iterator)localObject2).next();
                    if (((Nxt.Block)localObject1).previousBlock != Nxt.lastBlock)
                      continue;
                    ??? = ByteBuffer.allocate(224 + ((Nxt.Block)localObject1).payloadLength);
                    ((ByteBuffer)???).order(ByteOrder.LITTLE_ENDIAN);
                    ((ByteBuffer)???).put(((Nxt.Block)localObject1).getBytes());
                    for (k = 0; k < ((Nxt.Block)localObject1).transactions.length; ++k)
                      ((ByteBuffer)???).put(((Nxt.Transaction)localHashMap.get(Long.valueOf(localObject1.transactions[k]))).getBytes());
                    if (!Nxt.Block.pushBlock((ByteBuffer)???, false))
                      break;
                  }
                }
                if (Nxt.Block.getLastBlock().cumulativeDifficulty.compareTo(localBigInteger1) < 0)
                {
                  Nxt.Block.loadBlocks("blocks.nxt.bak");
                  Nxt.Transaction.loadTransactions("transactions.nxt.bak");
                  localPeer.blacklist();
                }
              }
            Nxt.Block.saveBlocks("blocks.nxt", false);
            Nxt.Transaction.saveTransactions("transactions.nxt");
          }
          catch (Exception localException)
          {
          }
        }
      }
      , 0L, 1L, TimeUnit.SECONDS);
      scheduledThreadPool.scheduleWithFixedDelay(new Runnable()
      {
        public void run()
        {
          try
          {
            HashMap localHashMap = new HashMap();
            Iterator localIterator = Nxt.users.values().iterator();
            Object localObject1;
            Nxt.Account localAccount;
            while (localIterator.hasNext())
            {
              localObject1 = (Nxt.User)localIterator.next();
              if (((Nxt.User)localObject1).secretPhrase == null)
                continue;
              localAccount = (Nxt.Account)Nxt.accounts.get(Long.valueOf(Nxt.Account.getId(Nxt.Crypto.getPublicKey(((Nxt.User)localObject1).secretPhrase))));
              if ((localAccount == null) || (localAccount.getEffectiveBalance() <= 0))
                continue;
              localHashMap.put(localAccount, localObject1);
            }
            localIterator = localHashMap.entrySet().iterator();
            while (localIterator.hasNext())
            {
              localObject1 = (Map.Entry)localIterator.next();
              localAccount = (Nxt.Account)((Map.Entry)localObject1).getKey();
              Nxt.User localUser = (Nxt.User)((Map.Entry)localObject1).getValue();
              Nxt.Block localBlock = Nxt.Block.getLastBlock();
              if (Nxt.lastBlocks.get(localAccount) != localBlock)
              {
                byte[] arrayOfByte = Nxt.Crypto.sign(localBlock.generationSignature, localUser.secretPhrase);
                localObject2 = MessageDigest.getInstance("SHA-256").digest(arrayOfByte);
                BigInteger localBigInteger = new BigInteger(1, new byte[] { localObject2[7], localObject2[6], localObject2[5], localObject2[4], localObject2[3], localObject2[2], localObject2[1], localObject2[0] });
                Nxt.lastBlocks.put(localAccount, localBlock);
                Nxt.hits.put(localAccount, localBigInteger);
                JSONObject localJSONObject = new JSONObject();
                localJSONObject.put("response", "setBlockGenerationDeadline");
                localJSONObject.put("deadline", Long.valueOf(localBigInteger.divide(BigInteger.valueOf(Nxt.Block.getBaseTarget()).multiply(BigInteger.valueOf(localAccount.getEffectiveBalance()))).longValue() - (Nxt.getEpochTime(System.currentTimeMillis()) - localBlock.timestamp)));
                localUser.send(localJSONObject);
              }
              int i = Nxt.getEpochTime(System.currentTimeMillis()) - localBlock.timestamp;
              if (i <= 0)
                continue;
              Object localObject2 = BigInteger.valueOf(Nxt.Block.getBaseTarget()).multiply(BigInteger.valueOf(localAccount.getEffectiveBalance())).multiply(BigInteger.valueOf(i));
              if (((BigInteger)Nxt.hits.get(localAccount)).compareTo((BigInteger)localObject2) >= 0)
                continue;
              localAccount.generateBlock(localUser.secretPhrase);
            }
          }
          catch (Exception localException)
          {
          }
        }
      }
      , 0L, 1L, TimeUnit.SECONDS);
    }
    catch (Exception localException1)
    {
      logMessage("10: " + localException1.toString());
    }
  }

  public void doGet(HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse)
    throws ServletException, IOException
  {
    Nxt.User localUser = null;
    Object localObject1;
    Object localObject4;
    label7953: label7978: Object localObject6;
    Object localObject3;
    try
    {
      String str1 = paramHttpServletRequest.getParameter("user");
      Object localObject2;
      Object localObject5;
      Object localObject26;
      Object localObject9;
      Object localObject21;
      if (str1 == null)
      {
        localObject1 = new JSONObject();
        Object localObject32;
        Object localObject33;
        byte[] arrayOfByte1;
        byte[] arrayOfByte4;
        Object localObject23;
        Object localObject28;
        Object localObject16;
        Object localObject20;
        Object localObject8;
        if ((allowedBotHosts != null) && (!allowedBotHosts.contains(paramHttpServletRequest.getRemoteHost())))
        {
          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(7));
          ((JSONObject)localObject1).put("errorDescription", "Not allowed");
        }
        else
        {
          localObject2 = paramHttpServletRequest.getParameter("requestType");
          if (localObject2 == null)
          {
            ((JSONObject)localObject1).put("errorCode", Integer.valueOf(1));
            ((JSONObject)localObject1).put("errorDescription", "Incorrect request");
          }
          else
          {
            switch ((localObject4 = localObject2).hashCode())
            {
            case -1836634766:
              if (((String)localObject4).equals("getAccountId"));
              break;
            case -1835768118:
              if (((String)localObject4).equals("getUnconfirmedTransactionIds"));
              break;
            case -1594290433:
              if (((String)localObject4).equals("getAccountPublicKey"));
              break;
            case -1415951151:
              if (((String)localObject4).equals("getAccountTransactionIds"));
              break;
            case -996573277:
              if (((String)localObject4).equals("getTransactionBytes"));
              break;
            case -944172977:
              if (((String)localObject4).equals("listAccountAliases"));
              break;
            case -907924844:
              if (((String)localObject4).equals("decodeHallmark"));
              break;
            case -502897730:
              if (((String)localObject4).equals("getAliasIds"));
              break;
            case -502886798:
              if (((String)localObject4).equals("getAliasURI"));
              break;
            case -431881575:
              if (((String)localObject4).equals("getConstants"));
              break;
            case -75245096:
              if (((String)localObject4).equals("getPeer"));
              break;
            case -75121853:
              if (((String)localObject4).equals("getTime"));
              break;
            case 9950744:
              if (((String)localObject4).equals("sendMoney"));
              break;
            case 62209885:
              if (((String)localObject4).equals("broadcastTransaction"));
              break;
            case 246104597:
              if (((String)localObject4).equals("markHost"));
              break;
            case 635655024:
              if (((String)localObject4).equals("getMyInfo"));
              break;
            case 697674406:
              if (((String)localObject4).equals("getBalance"));
              break;
            case 1183136939:
              if (((String)localObject4).equals("decodeToken"));
              break;
            case 1500977576:
              if (((String)localObject4).equals("getTransaction"));
              break;
            case 1708941985:
              if (((String)localObject4).equals("assignAlias"));
              break;
            case 1948728474:
              if (((String)localObject4).equals("getAlias"));
              break;
            case 1949657815:
              if (((String)localObject4).equals("getBlock"));
              break;
            case 1962369435:
              if (((String)localObject4).equals("getPeers"));
              break;
            case 1965583067:
              if (!((String)localObject4).equals("getState"))
              {
                break label7953:
                localObject5 = paramHttpServletRequest.getParameter("secretPhrase");
                Object localObject7 = paramHttpServletRequest.getParameter("alias");
                Object localObject10 = paramHttpServletRequest.getParameter("uri");
                Object localObject12 = paramHttpServletRequest.getParameter("fee");
                Object localObject15 = paramHttpServletRequest.getParameter("deadline");
                Object localObject19 = paramHttpServletRequest.getParameter("referencedTransaction");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"secretPhrase\" not specified");
                  break label7978:
                }
                if (localObject7 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"alias\" not specified");
                  break label7978:
                }
                if (localObject10 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"uri\" not specified");
                  break label7978:
                }
                if (localObject12 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"fee\" not specified");
                  break label7978:
                }
                if (localObject15 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"deadline\" not specified");
                  break label7978:
                }
                localObject7 = ((String)localObject7).trim();
                if ((((String)localObject7).length() == 0) || (((String)localObject7).length() > 100))
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"alias\" (length must be in [1..100] range)");
                  break label7978:
                }
                String str4 = ((String)localObject7).toLowerCase();
                for (int i13 = 0; i13 < str4.length(); ++i13)
                  if ("0123456789abcdefghijklmnopqrstuvwxyz".indexOf(str4.charAt(i13)) < 0)
                    break;
                if (i13 != str4.length())
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"alias\" (must contain only digits and latin letters)");
                  break label7978:
                }
                localObject10 = ((String)localObject10).trim();
                if (((String)localObject10).length() > 1000)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"uri\" (length must be not longer than 1000 characters)");
                  break label7978:
                }
                int i16;
                try
                {
                  i16 = Integer.parseInt((String)localObject12);
                  if ((i16 <= 0) || (i16 >= 1000000000))
                    throw new Exception();
                  try
                  {
                    short s1 = Short.parseShort((String)localObject15);
                    if (s1 < 1)
                      throw new Exception();
                    long l11 = (localObject19 == null) ? 0L : new BigInteger((String)localObject19).longValue();
                    byte[] arrayOfByte3 = Nxt.Crypto.getPublicKey((String)localObject5);
                    long l13 = Nxt.Account.getId(arrayOfByte3);
                    localObject32 = (Nxt.Account)accounts.get(Long.valueOf(l13));
                    if (localObject32 == null)
                    {
                      ((JSONObject)localObject1).put("errorCode", Integer.valueOf(6));
                      ((JSONObject)localObject1).put("errorDescription", "Not enough funds");
                    }
                    else if (i16 * 100L > ((Nxt.Account)localObject32).unconfirmedBalance)
                    {
                      ((JSONObject)localObject1).put("errorCode", Integer.valueOf(6));
                      ((JSONObject)localObject1).put("errorDescription", "Not enough funds");
                    }
                    else
                    {
                      synchronized (aliases)
                      {
                        localObject33 = (Nxt.Alias)aliases.get(str4);
                      }
                      if ((localObject33 != null) && (((Nxt.Alias)localObject33).account != localObject32))
                      {
                        ((JSONObject)localObject1).put("errorCode", Integer.valueOf(8));
                        ((JSONObject)localObject1).put("errorDescription", "\"" + (String)localObject7 + "\" is already used");
                      }
                      else
                      {
                        int i22 = getEpochTime(System.currentTimeMillis());
                        Nxt.Transaction localTransaction = new Nxt.Transaction(1, 1, i22, s1, arrayOfByte3, 1739068987193023818L, 0, i16, l11, new byte[64]);
                        localTransaction.attachment = new Nxt.Transaction.MessagingAliasAssignmentAttachment((String)localObject7, (String)localObject10);
                        localTransaction.sign((String)localObject5);
                        JSONObject localJSONObject5 = new JSONObject();
                        localJSONObject5.put("requestType", "processTransactions");
                        JSONArray localJSONArray3 = new JSONArray();
                        localJSONArray3.add(localTransaction.getJSONObject());
                        localJSONObject5.put("transactions", localJSONArray3);
                        Nxt.Peer.sendToAllPeers(localJSONObject5);
                        ((JSONObject)localObject1).put("transaction", convert(localTransaction.getId()));
                      }
                    }
                  }
                  catch (Exception localException2)
                  {
                    ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                    ((JSONObject)localObject1).put("errorDescription", "Incorrect \"deadline\"");
                  }
                }
                catch (Exception localException3)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"fee\"");
                }
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("transactionBytes");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"transactionBytes\" not specified");
                  break label7978:
                }
                try
                {
                  localObject7 = ByteBuffer.wrap(convert((String)localObject5));
                  ((ByteBuffer)localObject7).order(ByteOrder.LITTLE_ENDIAN);
                  localObject10 = Nxt.Transaction.getTransaction((ByteBuffer)localObject7);
                  localObject12 = new JSONObject();
                  ((JSONObject)localObject12).put("requestType", "processTransactions");
                  localObject15 = new JSONArray();
                  ((JSONArray)localObject15).add(((Nxt.Transaction)localObject10).getJSONObject());
                  ((JSONObject)localObject12).put("transactions", localObject15);
                  Nxt.Peer.sendToAllPeers((JSONObject)localObject12);
                  ((JSONObject)localObject1).put("transaction", convert(((Nxt.Transaction)localObject10).getId()));
                }
                catch (Exception localException4)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"transactionBytes\"");
                }
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("hallmark");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"hallmark\" not specified");
                  break label7978:
                }
                try
                {
                  localObject7 = convert((String)localObject5);
                  localObject10 = ByteBuffer.wrap(localObject7);
                  ((ByteBuffer)localObject10).order(ByteOrder.LITTLE_ENDIAN);
                  localObject12 = new byte[32];
                  ((ByteBuffer)localObject10).get(localObject12);
                  i5 = ((ByteBuffer)localObject10).getShort();
                  localObject19 = new byte[i5];
                  ((ByteBuffer)localObject10).get(localObject19);
                  str4 = new String(localObject19, "UTF-8");
                  i13 = ((ByteBuffer)localObject10).getInt();
                  i16 = ((ByteBuffer)localObject10).getInt();
                  ((ByteBuffer)localObject10).get();
                  arrayOfByte1 = new byte[64];
                  ((ByteBuffer)localObject10).get(arrayOfByte1);
                  ((JSONObject)localObject1).put("account", convert(Nxt.Account.getId(localObject12)));
                  ((JSONObject)localObject1).put("host", str4);
                  ((JSONObject)localObject1).put("weight", Integer.valueOf(i13));
                  int i19 = i16 / 10000;
                  int i20 = i16 % 10000 / 100;
                  int i21 = i16 % 100;
                  ((JSONObject)localObject1).put("date", ((i19 < 1000) ? "0" : (i19 < 100) ? "00" : (i19 < 10) ? "000" : "") + i19 + "-" + ((i20 < 10) ? "0" : "") + i20 + "-" + ((i21 < 10) ? "0" : "") + i21);
                  arrayOfByte4 = new byte[localObject7.length - 64];
                  System.arraycopy(localObject7, 0, arrayOfByte4, 0, arrayOfByte4.length);
                  ((JSONObject)localObject1).put("valid", Boolean.valueOf(((str4.length() > 100) || (i13 <= 0) || (i13 > 1000000000)) ? false : Nxt.Crypto.verify(arrayOfByte1, arrayOfByte4, localObject12)));
                }
                catch (Exception localException5)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"hallmark\"");
                }
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("website");
                localObject7 = paramHttpServletRequest.getParameter("token");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"website\" not specified");
                  break label7978:
                }
                if (localObject7 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"token\" not specified");
                  break label7978:
                }
                localObject10 = ((String)localObject5).trim().getBytes("UTF-8");
                localObject12 = new byte[100];
                int i5 = 0;
                int i8 = 0;
                try
                {
                  while (i5 < ((String)localObject7).length())
                  {
                    long l9 = Long.parseLong(((String)localObject7).substring(i5, i5 + 8), 32);
                    localObject12[i8] = (byte)(int)l9;
                    localObject12[(i8 + 1)] = (byte)(int)(l9 >> 8);
                    localObject12[(i8 + 2)] = (byte)(int)(l9 >> 16);
                    localObject12[(i8 + 3)] = (byte)(int)(l9 >> 24);
                    localObject12[(i8 + 4)] = (byte)(int)(l9 >> 32);
                    i5 += 8;
                    i8 += 5;
                  }
                }
                catch (Exception localException6)
                {
                }
                if (i5 != 160)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"token\"");
                  break label7978:
                }
                localObject23 = new byte[32];
                System.arraycopy(localObject12, 0, localObject23, 0, 32);
                i13 = localObject12[32] & 0xFF | (localObject12[33] & 0xFF) << 8 | (localObject12[34] & 0xFF) << 16 | (localObject12[35] & 0xFF) << 24;
                localObject28 = new byte[64];
                System.arraycopy(localObject12, 36, localObject28, 0, 64);
                arrayOfByte1 = new byte[localObject10.length + 36];
                System.arraycopy(localObject10, 0, arrayOfByte1, 0, localObject10.length);
                System.arraycopy(localObject12, 0, arrayOfByte1, localObject10.length, 36);
                boolean bool = Nxt.Crypto.verify(localObject28, arrayOfByte1, localObject23);
                ((JSONObject)localObject1).put("account", convert(Nxt.Account.getId(localObject23)));
                ((JSONObject)localObject1).put("timestamp", Integer.valueOf(i13));
                ((JSONObject)localObject1).put("valid", Boolean.valueOf(bool));
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("secretPhrase");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"secretPhrase\" not specified");
                  break label7978:
                }
                localObject7 = MessageDigest.getInstance("SHA-256").digest(Nxt.Crypto.getPublicKey((String)localObject5));
                localObject10 = new BigInteger(1, new byte[] { localObject7[7], localObject7[6], localObject7[5], localObject7[4], localObject7[3], localObject7[2], localObject7[1], localObject7[0] });
                ((JSONObject)localObject1).put("accountId", ((BigInteger)localObject10).toString());
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("account");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"account\" not specified");
                  break label7978:
                }
                try
                {
                  long l1 = new BigInteger((String)localObject5).longValue();
                  localObject12 = (Nxt.Account)accounts.get(Long.valueOf(l1));
                  if (localObject12 == null)
                  {
                    ((JSONObject)localObject1).put("errorCode", Integer.valueOf(5));
                    ((JSONObject)localObject1).put("errorDescription", "Unknown account");
                  }
                  else if (((Nxt.Account)localObject12).publicKey != null)
                  {
                    ((JSONObject)localObject1).put("publicKey", convert(((Nxt.Account)localObject12).publicKey));
                  }
                }
                catch (Exception localException7)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"account\"");
                }
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("account");
                String str2 = paramHttpServletRequest.getParameter("timestamp");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"account\" not specified");
                  break label7978:
                }
                if (str2 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"timestamp\" not specified");
                  break label7978:
                }
                try
                {
                  localObject10 = (Nxt.Account)accounts.get(Long.valueOf(new BigInteger((String)localObject5).longValue()));
                  if (localObject10 == null)
                  {
                    ((JSONObject)localObject1).put("errorCode", Integer.valueOf(5));
                    ((JSONObject)localObject1).put("errorDescription", "Unknown account");
                  }
                  else
                  {
                    try
                    {
                      int i2 = Integer.parseInt(str2);
                      if (i2 < 0)
                        throw new Exception();
                      localObject16 = new JSONArray();
                      localObject23 = transactions.entrySet().iterator();
                      while (((Iterator)localObject23).hasNext())
                      {
                        localObject20 = (Map.Entry)((Iterator)localObject23).next();
                        localObject26 = (Nxt.Transaction)((Map.Entry)localObject20).getValue();
                        if ((((Nxt.Block)blocks.get(Long.valueOf(((Nxt.Transaction)localObject26).block))).timestamp < i2) || ((Nxt.Account.getId(((Nxt.Transaction)localObject26).senderPublicKey) != ((Nxt.Account)localObject10).id) && (((Nxt.Transaction)localObject26).recipient != ((Nxt.Account)localObject10).id)))
                          continue;
                        ((JSONArray)localObject16).add(convert(((Long)((Map.Entry)localObject20).getKey()).longValue()));
                      }
                      ((JSONObject)localObject1).put("transactionIds", localObject16);
                    }
                    catch (Exception localException8)
                    {
                      ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                      ((JSONObject)localObject1).put("errorDescription", "Incorrect \"timestamp\"");
                    }
                  }
                }
                catch (Exception localException9)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"account\"");
                }
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("alias");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"alias\" not specified");
                  break label7978:
                }
                Object localObject13;
                try
                {
                  long l2 = new BigInteger((String)localObject5).longValue();
                  localObject13 = (Nxt.Alias)aliasIdToAliasMappings.get(Long.valueOf(l2));
                  if (localObject13 == null)
                  {
                    ((JSONObject)localObject1).put("errorCode", Integer.valueOf(5));
                    ((JSONObject)localObject1).put("errorDescription", "Unknown alias");
                  }
                  else
                  {
                    ((JSONObject)localObject1).put("account", convert(((Nxt.Alias)localObject13).account.id));
                    ((JSONObject)localObject1).put("alias", ((Nxt.Alias)localObject13).alias);
                    if (((Nxt.Alias)localObject13).uri.length() > 0)
                      ((JSONObject)localObject1).put("uri", ((Nxt.Alias)localObject13).uri);
                    ((JSONObject)localObject1).put("timestamp", Integer.valueOf(((Nxt.Alias)localObject13).timestamp));
                  }
                }
                catch (Exception localException10)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"alias\"");
                }
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("timestamp");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"timestamp\" not specified");
                  break label7978:
                }
                try
                {
                  int i1 = Integer.parseInt((String)localObject5);
                  if (i1 < 0)
                    throw new Exception();
                  localObject10 = new JSONArray();
                  localObject16 = aliasIdToAliasMappings.entrySet().iterator();
                  while (((Iterator)localObject16).hasNext())
                  {
                    localObject13 = (Map.Entry)((Iterator)localObject16).next();
                    if (((Nxt.Alias)((Map.Entry)localObject13).getValue()).timestamp < i1)
                      continue;
                    ((JSONArray)localObject10).add(convert(((Long)((Map.Entry)localObject13).getKey()).longValue()));
                  }
                  ((JSONObject)localObject1).put("aliasIds", localObject10);
                }
                catch (Exception localException11)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"timestamp\"");
                }
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("alias");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"alias\" not specified");
                  break label7978:
                }
                localObject8 = (Nxt.Alias)aliases.get(((String)localObject5).toLowerCase());
                if (localObject8 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(5));
                  ((JSONObject)localObject1).put("errorDescription", "Unknown alias");
                  break label7978:
                }
                if (((Nxt.Alias)localObject8).uri.length() <= 0)
                  break label7978;
                ((JSONObject)localObject1).put("uri", ((Nxt.Alias)localObject8).uri);
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("account");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"account\" not specified");
                }
              }
            }
          }
        }
        try
        {
          localObject8 = (Nxt.Account)accounts.get(Long.valueOf(new BigInteger((String)localObject5).longValue()));
          if (localObject8 == null)
          {
            ((JSONObject)localObject1).put("balance", Integer.valueOf(0));
            ((JSONObject)localObject1).put("unconfirmedBalance", Integer.valueOf(0));
            ((JSONObject)localObject1).put("effectiveBalance", Integer.valueOf(0));
          }
          else
          {
            synchronized (localObject8)
            {
              ((JSONObject)localObject1).put("balance", Long.valueOf(((Nxt.Account)localObject8).balance));
              ((JSONObject)localObject1).put("unconfirmedBalance", Long.valueOf(((Nxt.Account)localObject8).unconfirmedBalance));
              ((JSONObject)localObject1).put("effectiveBalance", Long.valueOf(((Nxt.Account)localObject8).getEffectiveBalance() * 100L));
            }
          }
        }
        catch (Exception localException12)
        {
          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
          ((JSONObject)localObject1).put("errorDescription", "Incorrect \"account\"");
          break label7978:
          localObject5 = paramHttpServletRequest.getParameter("block");
          if (localObject5 == null)
          {
            ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
            ((JSONObject)localObject1).put("errorDescription", "\"block\" not specified");
          }
          else
          {
            try
            {
              localObject8 = (Nxt.Block)blocks.get(Long.valueOf(new BigInteger((String)localObject5).longValue()));
              if (localObject8 == null)
              {
                ((JSONObject)localObject1).put("errorCode", Integer.valueOf(5));
                ((JSONObject)localObject1).put("errorDescription", "Unknown block");
              }
              else
              {
                ((JSONObject)localObject1).put("height", Integer.valueOf(((Nxt.Block)localObject8).height));
                ((JSONObject)localObject1).put("generator", convert(Nxt.Account.getId(((Nxt.Block)localObject8).generatorPublicKey)));
                ((JSONObject)localObject1).put("timestamp", Integer.valueOf(((Nxt.Block)localObject8).timestamp));
                ((JSONObject)localObject1).put("numberOfTransactions", Integer.valueOf(((Nxt.Block)localObject8).numberOfTransactions));
                ((JSONObject)localObject1).put("totalAmount", Integer.valueOf(((Nxt.Block)localObject8).totalAmount));
                ((JSONObject)localObject1).put("totalFee", Integer.valueOf(((Nxt.Block)localObject8).totalFee));
                ((JSONObject)localObject1).put("payloadLength", Integer.valueOf(((Nxt.Block)localObject8).payloadLength));
                ((JSONObject)localObject1).put("version", Integer.valueOf(((Nxt.Block)localObject8).version));
                ((JSONObject)localObject1).put("baseTarget", convert(((Nxt.Block)localObject8).baseTarget));
                if (((Nxt.Block)localObject8).previousBlock != 0L)
                  ((JSONObject)localObject1).put("previousBlock", convert(((Nxt.Block)localObject8).previousBlock));
                if (((Nxt.Block)localObject8).nextBlock != 0L)
                  ((JSONObject)localObject1).put("nextBlock", convert(((Nxt.Block)localObject8).nextBlock));
                ((JSONObject)localObject1).put("payloadHash", convert(((Nxt.Block)localObject8).payloadHash));
                ((JSONObject)localObject1).put("generationSignature", convert(((Nxt.Block)localObject8).generationSignature));
                ((JSONObject)localObject1).put("blockSignature", convert(((Nxt.Block)localObject8).blockSignature));
                ??? = new JSONArray();
                for (int i3 = 0; i3 < ((Nxt.Block)localObject8).numberOfTransactions; ++i3)
                  ((JSONArray)???).add(convert(localObject8.transactions[i3]));
                ((JSONObject)localObject1).put("transactions", ???);
              }
            }
            catch (Exception localException13)
            {
              ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
              ((JSONObject)localObject1).put("errorDescription", "Incorrect \"block\"");
            }
            break label7978:
            localObject5 = new JSONArray();
            localObject8 = new JSONObject();
            ((JSONObject)localObject8).put("value", Byte.valueOf(0));
            ((JSONObject)localObject8).put("description", "Payment");
            ??? = new JSONArray();
            Object localObject14 = new JSONObject();
            ((JSONObject)localObject14).put("value", Byte.valueOf(0));
            ((JSONObject)localObject14).put("description", "Ordinary payment");
            ((JSONArray)???).add(localObject14);
            ((JSONObject)localObject8).put("subtypes", ???);
            ((JSONArray)localObject5).add(localObject8);
            localObject8 = new JSONObject();
            ((JSONObject)localObject8).put("value", Byte.valueOf(1));
            ((JSONObject)localObject8).put("description", "Messaging");
            ??? = new JSONArray();
            localObject14 = new JSONObject();
            ((JSONObject)localObject14).put("value", Byte.valueOf(0));
            ((JSONObject)localObject14).put("description", "Arbitrary message");
            ((JSONArray)???).add(localObject14);
            localObject14 = new JSONObject();
            ((JSONObject)localObject14).put("value", Byte.valueOf(1));
            ((JSONObject)localObject14).put("description", "Alias assignment");
            ((JSONArray)???).add(localObject14);
            ((JSONObject)localObject8).put("subtypes", ???);
            ((JSONArray)localObject5).add(localObject8);
            localObject8 = new JSONObject();
            ((JSONObject)localObject8).put("value", Byte.valueOf(2));
            ((JSONObject)localObject8).put("description", "Colored coins");
            ??? = new JSONArray();
            localObject14 = new JSONObject();
            ((JSONObject)localObject14).put("value", Byte.valueOf(0));
            ((JSONObject)localObject14).put("description", "Asset issuance");
            ((JSONArray)???).add(localObject14);
            localObject14 = new JSONObject();
            ((JSONObject)localObject14).put("value", Byte.valueOf(1));
            ((JSONObject)localObject14).put("description", "Asset transfer");
            ((JSONArray)???).add(localObject14);
            localObject14 = new JSONObject();
            ((JSONObject)localObject14).put("value", Byte.valueOf(2));
            ((JSONObject)localObject14).put("description", "Ask order placement");
            ((JSONArray)???).add(localObject14);
            localObject14 = new JSONObject();
            ((JSONObject)localObject14).put("value", Byte.valueOf(3));
            ((JSONObject)localObject14).put("description", "Bid order placement");
            ((JSONArray)???).add(localObject14);
            localObject14 = new JSONObject();
            ((JSONObject)localObject14).put("value", Byte.valueOf(4));
            ((JSONObject)localObject14).put("description", "Ask order cancellation");
            ((JSONArray)???).add(localObject14);
            localObject14 = new JSONObject();
            ((JSONObject)localObject14).put("value", Byte.valueOf(5));
            ((JSONObject)localObject14).put("description", "Bid order cancellation");
            ((JSONArray)???).add(localObject14);
            ((JSONObject)localObject8).put("subtypes", ???);
            ((JSONArray)localObject5).add(localObject8);
            ((JSONObject)localObject1).put("transactionTypes", localObject5);
            localObject16 = new JSONArray();
            localObject20 = new JSONObject();
            ((JSONObject)localObject20).put("value", Integer.valueOf(0));
            ((JSONObject)localObject20).put("description", "Non-connected");
            ((JSONArray)localObject16).add(localObject20);
            localObject20 = new JSONObject();
            ((JSONObject)localObject20).put("value", Integer.valueOf(1));
            ((JSONObject)localObject20).put("description", "Connected");
            ((JSONArray)localObject16).add(localObject20);
            localObject20 = new JSONObject();
            ((JSONObject)localObject20).put("value", Integer.valueOf(2));
            ((JSONObject)localObject20).put("description", "Disconnected");
            ((JSONArray)localObject16).add(localObject20);
            ((JSONObject)localObject1).put("peerStates", localObject16);
            break label7978:
            ((JSONObject)localObject1).put("host", paramHttpServletRequest.getRemoteHost());
            ((JSONObject)localObject1).put("address", paramHttpServletRequest.getRemoteAddr());
            break label7978:
            localObject5 = paramHttpServletRequest.getParameter("peer");
            if (localObject5 == null)
            {
              ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
              ((JSONObject)localObject1).put("errorDescription", "\"peer\" not specified");
            }
            else
            {
              localObject8 = (Nxt.Peer)peers.get(localObject5);
              if (localObject8 == null)
              {
                ((JSONObject)localObject1).put("errorCode", Integer.valueOf(5));
                ((JSONObject)localObject1).put("errorDescription", "Unknown peer");
              }
              else
              {
                ((JSONObject)localObject1).put("state", Integer.valueOf(((Nxt.Peer)localObject8).state));
                ((JSONObject)localObject1).put("announcedAddress", ((Nxt.Peer)localObject8).announcedAddress);
                if (((Nxt.Peer)localObject8).hallmark != null)
                  ((JSONObject)localObject1).put("hallmark", ((Nxt.Peer)localObject8).hallmark);
                ((JSONObject)localObject1).put("weight", Integer.valueOf(((Nxt.Peer)localObject8).getWeight()));
                ((JSONObject)localObject1).put("downloadedVolume", Long.valueOf(((Nxt.Peer)localObject8).downloadedVolume));
                ((JSONObject)localObject1).put("uploadedVolume", Long.valueOf(((Nxt.Peer)localObject8).uploadedVolume));
                ((JSONObject)localObject1).put("application", ((Nxt.Peer)localObject8).application);
                ((JSONObject)localObject1).put("version", ((Nxt.Peer)localObject8).version);
                break label7978:
                localObject5 = new JSONArray();
                synchronized (peers)
                {
                  localObject8 = ((HashMap)peers.clone()).keySet();
                }
                localObject14 = ((Set)localObject8).iterator();
                while (((Iterator)localObject14).hasNext())
                {
                  ??? = (String)((Iterator)localObject14).next();
                  ((JSONArray)localObject5).add(???);
                }
                ((JSONObject)localObject1).put("peers", localObject5);
                break label7978:
                ((JSONObject)localObject1).put("version", "0.4.2");
                ((JSONObject)localObject1).put("time", Integer.valueOf(getEpochTime(System.currentTimeMillis())));
                ((JSONObject)localObject1).put("lastBlock", convert(lastBlock));
                ((JSONObject)localObject1).put("numberOfBlocks", Integer.valueOf(blocks.size()));
                ((JSONObject)localObject1).put("numberOfTransactions", Integer.valueOf(transactions.size()));
                ((JSONObject)localObject1).put("numberOfAccounts", Integer.valueOf(accounts.size()));
                ((JSONObject)localObject1).put("numberOfAssets", Integer.valueOf(assets.size()));
                ((JSONObject)localObject1).put("numberOfOrders", Integer.valueOf(askOrders.size() + bidOrders.size()));
                ((JSONObject)localObject1).put("numberOfAliases", Integer.valueOf(aliases.size()));
                ((JSONObject)localObject1).put("numberOfUsers", Integer.valueOf(users.size()));
                ((JSONObject)localObject1).put("lastBlockchainFeeder", (lastBlockchainFeeder == null) ? null : lastBlockchainFeeder.announcedAddress);
                ((JSONObject)localObject1).put("availableProcessors", Integer.valueOf(Runtime.getRuntime().availableProcessors()));
                ((JSONObject)localObject1).put("maxMemory", Long.valueOf(Runtime.getRuntime().maxMemory()));
                ((JSONObject)localObject1).put("totalMemory", Long.valueOf(Runtime.getRuntime().totalMemory()));
                ((JSONObject)localObject1).put("freeMemory", Long.valueOf(Runtime.getRuntime().freeMemory()));
                break label7978:
                ((JSONObject)localObject1).put("time", Integer.valueOf(getEpochTime(System.currentTimeMillis())));
                break label7978:
                localObject5 = paramHttpServletRequest.getParameter("transaction");
                if (localObject5 == null)
                {
                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                  ((JSONObject)localObject1).put("errorDescription", "\"transaction\" not specified");
                }
                else
                {
                  long l3;
                  try
                  {
                    l3 = new BigInteger((String)localObject5).longValue();
                    localObject14 = (Nxt.Transaction)transactions.get(Long.valueOf(l3));
                    if (localObject14 == null)
                    {
                      localObject14 = (Nxt.Transaction)unconfirmedTransactions.get(Long.valueOf(l3));
                      if (localObject14 == null)
                      {
                        ((JSONObject)localObject1).put("errorCode", Integer.valueOf(5));
                        ((JSONObject)localObject1).put("errorDescription", "Unknown transaction");
                      }
                      else
                      {
                        localObject1 = ((Nxt.Transaction)localObject14).getJSONObject();
                        ((JSONObject)localObject1).put("sender", convert(Nxt.Account.getId(((Nxt.Transaction)localObject14).senderPublicKey)));
                      }
                    }
                    else
                    {
                      localObject1 = ((Nxt.Transaction)localObject14).getJSONObject();
                      ((JSONObject)localObject1).put("sender", convert(Nxt.Account.getId(((Nxt.Transaction)localObject14).senderPublicKey)));
                      localObject16 = (Nxt.Block)blocks.get(Long.valueOf(((Nxt.Transaction)localObject14).block));
                      ((JSONObject)localObject1).put("block", convert(((Nxt.Block)localObject16).getId()));
                      ((JSONObject)localObject1).put("confirmations", Integer.valueOf(Nxt.Block.getLastBlock().height - ((Nxt.Block)localObject16).height + 1));
                    }
                  }
                  catch (Exception localException14)
                  {
                    ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                    ((JSONObject)localObject1).put("errorDescription", "Incorrect \"transaction\"");
                  }
                  break label7978:
                  localObject5 = paramHttpServletRequest.getParameter("transaction");
                  if (localObject5 == null)
                  {
                    ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                    ((JSONObject)localObject1).put("errorDescription", "\"transaction\" not specified");
                  }
                  else
                  {
                    try
                    {
                      l3 = new BigInteger((String)localObject5).longValue();
                      localObject14 = (Nxt.Transaction)transactions.get(Long.valueOf(l3));
                      if (localObject14 == null)
                      {
                        localObject14 = (Nxt.Transaction)unconfirmedTransactions.get(Long.valueOf(l3));
                        if (localObject14 == null)
                        {
                          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(5));
                          ((JSONObject)localObject1).put("errorDescription", "Unknown transaction");
                        }
                        else
                        {
                          ((JSONObject)localObject1).put("bytes", convert(((Nxt.Transaction)localObject14).getBytes()));
                        }
                      }
                      else
                      {
                        ((JSONObject)localObject1).put("bytes", convert(((Nxt.Transaction)localObject14).getBytes()));
                        localObject16 = (Nxt.Block)blocks.get(Long.valueOf(((Nxt.Transaction)localObject14).block));
                        ((JSONObject)localObject1).put("confirmations", Integer.valueOf(Nxt.Block.getLastBlock().height - ((Nxt.Block)localObject16).height + 1));
                      }
                    }
                    catch (Exception localException15)
                    {
                      ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                      ((JSONObject)localObject1).put("errorDescription", "Incorrect \"transaction\"");
                    }
                    break label7978:
                    localObject5 = new JSONArray();
                    ??? = unconfirmedTransactions.keySet().iterator();
                    while (((Iterator)???).hasNext())
                    {
                      Long localLong = (Long)((Iterator)???).next();
                      ((JSONArray)localObject5).add(convert(localLong.longValue()));
                    }
                    ((JSONObject)localObject1).put("unconfirmedTransactionIds", localObject5);
                    break label7978:
                    localObject5 = paramHttpServletRequest.getParameter("account");
                    if (localObject5 == null)
                    {
                      ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                      ((JSONObject)localObject1).put("errorDescription", "\"account\" not specified");
                    }
                    else
                    {
                      try
                      {
                        long l4 = new BigInteger((String)localObject5).longValue();
                        localObject14 = (Nxt.Account)accounts.get(Long.valueOf(l4));
                        if (localObject14 == null)
                        {
                          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(5));
                          ((JSONObject)localObject1).put("errorDescription", "Unknown account");
                        }
                        else
                        {
                          localObject16 = new JSONArray();
                          localObject23 = aliases.values().iterator();
                          while (((Iterator)localObject23).hasNext())
                          {
                            localObject20 = (Nxt.Alias)((Iterator)localObject23).next();
                            if (((Nxt.Alias)localObject20).account.id != l4)
                              continue;
                            localObject26 = new JSONObject();
                            ((JSONObject)localObject26).put("alias", ((Nxt.Alias)localObject20).alias);
                            ((JSONObject)localObject26).put("uri", ((Nxt.Alias)localObject20).uri);
                            ((JSONArray)localObject16).add(localObject26);
                          }
                          ((JSONObject)localObject1).put("aliases", localObject16);
                        }
                      }
                      catch (Exception localException16)
                      {
                        ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                        ((JSONObject)localObject1).put("errorDescription", "Incorrect \"account\"");
                      }
                      break label7978:
                      localObject5 = paramHttpServletRequest.getParameter("secretPhrase");
                      localObject9 = paramHttpServletRequest.getParameter("host");
                      ??? = paramHttpServletRequest.getParameter("weight");
                      localObject14 = paramHttpServletRequest.getParameter("date");
                      if (localObject5 == null)
                      {
                        ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                        ((JSONObject)localObject1).put("errorDescription", "\"secretPhrase\" not specified");
                      }
                      else if (localObject9 == null)
                      {
                        ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                        ((JSONObject)localObject1).put("errorDescription", "\"host\" not specified");
                      }
                      else if (??? == null)
                      {
                        ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                        ((JSONObject)localObject1).put("errorDescription", "\"weight\" not specified");
                      }
                      else if (localObject14 == null)
                      {
                        ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                        ((JSONObject)localObject1).put("errorDescription", "\"date\" not specified");
                      }
                      else if (((String)localObject9).length() > 100)
                      {
                        ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                        ((JSONObject)localObject1).put("errorDescription", "Incorrect \"host\" (the length exceeds 100 chars limit)");
                      }
                      else
                      {
                        try
                        {
                          int i6 = Integer.parseInt((String)???);
                          if ((i6 <= 0) || (i6 > 1000000000))
                            throw new Exception();
                          try
                          {
                            int i9 = Integer.parseInt(((String)localObject14).substring(0, 4)) * 10000 + Integer.parseInt(((String)localObject14).substring(5, 7)) * 100 + Integer.parseInt(((String)localObject14).substring(8, 10));
                            localObject23 = Nxt.Crypto.getPublicKey((String)localObject5);
                            localObject26 = ((String)localObject9).getBytes("UTF-8");
                            localObject28 = ByteBuffer.allocate(34 + localObject26.length + 4 + 4 + 1);
                            ((ByteBuffer)localObject28).order(ByteOrder.LITTLE_ENDIAN);
                            ((ByteBuffer)localObject28).put(localObject23);
                            ((ByteBuffer)localObject28).putShort((short)localObject26.length);
                            ((ByteBuffer)localObject28).put(localObject26);
                            ((ByteBuffer)localObject28).putInt(i6);
                            ((ByteBuffer)localObject28).putInt(i9);
                            arrayOfByte1 = ((ByteBuffer)localObject28).array();
                            byte[] arrayOfByte2;
                            do
                            {
                              arrayOfByte1[(arrayOfByte1.length - 1)] = (byte)ThreadLocalRandom.current().nextInt();
                              arrayOfByte2 = Nxt.Crypto.sign(arrayOfByte1, (String)localObject5);
                            }
                            while (!Nxt.Crypto.verify(arrayOfByte2, arrayOfByte1, localObject23));
                            ((JSONObject)localObject1).put("hallmark", convert(arrayOfByte1) + convert(arrayOfByte2));
                          }
                          catch (Exception localException17)
                          {
                            ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                            ((JSONObject)localObject1).put("errorDescription", "Incorrect \"date\"");
                          }
                        }
                        catch (Exception localException18)
                        {
                          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                          ((JSONObject)localObject1).put("errorDescription", "Incorrect \"weight\"");
                        }
                        break label7978:
                        localObject5 = paramHttpServletRequest.getParameter("secretPhrase");
                        localObject9 = paramHttpServletRequest.getParameter("recipient");
                        ??? = paramHttpServletRequest.getParameter("amount");
                        localObject14 = paramHttpServletRequest.getParameter("fee");
                        String str3 = paramHttpServletRequest.getParameter("deadline");
                        localObject21 = paramHttpServletRequest.getParameter("referencedTransaction");
                        if (localObject5 == null)
                        {
                          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                          ((JSONObject)localObject1).put("errorDescription", "\"secretPhrase\" not specified");
                        }
                        else if (localObject9 == null)
                        {
                          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                          ((JSONObject)localObject1).put("errorDescription", "\"recipient\" not specified");
                        }
                        else if (??? == null)
                        {
                          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                          ((JSONObject)localObject1).put("errorDescription", "\"amount\" not specified");
                        }
                        else if (localObject14 == null)
                        {
                          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                          ((JSONObject)localObject1).put("errorDescription", "\"fee\" not specified");
                        }
                        else if (str3 == null)
                        {
                          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(3));
                          ((JSONObject)localObject1).put("errorDescription", "\"deadline\" not specified");
                        }
                        else
                        {
                          try
                          {
                            long l10 = new BigInteger((String)localObject9).longValue();
                            try
                            {
                              int i17 = Integer.parseInt((String)???);
                              if ((i17 <= 0) || (i17 >= 1000000000))
                                throw new Exception();
                              try
                              {
                                int i18 = Integer.parseInt((String)localObject14);
                                if ((i18 <= 0) || (i18 >= 1000000000))
                                  throw new Exception();
                                try
                                {
                                  short s2 = Short.parseShort(str3);
                                  if (s2 < 1)
                                    throw new Exception();
                                  long l12 = (localObject21 == null) ? 0L : new BigInteger((String)localObject21).longValue();
                                  arrayOfByte4 = Nxt.Crypto.getPublicKey((String)localObject5);
                                  Nxt.Account localAccount = (Nxt.Account)accounts.get(Long.valueOf(Nxt.Account.getId(arrayOfByte4)));
                                  if (localAccount == null)
                                  {
                                    ((JSONObject)localObject1).put("errorCode", Integer.valueOf(6));
                                    ((JSONObject)localObject1).put("errorDescription", "Not enough funds");
                                  }
                                  else if ((i17 + i18) * 100L > localAccount.unconfirmedBalance)
                                  {
                                    ((JSONObject)localObject1).put("errorCode", Integer.valueOf(6));
                                    ((JSONObject)localObject1).put("errorDescription", "Not enough funds");
                                  }
                                  else
                                  {
                                    localObject32 = new Nxt.Transaction(0, 0, getEpochTime(System.currentTimeMillis()), s2, arrayOfByte4, l10, i17, i18, l12, new byte[64]);
                                    ((Nxt.Transaction)localObject32).sign((String)localObject5);
                                    localObject33 = new JSONObject();
                                    ((JSONObject)localObject33).put("requestType", "processTransactions");
                                    JSONArray localJSONArray2 = new JSONArray();
                                    localJSONArray2.add(((Nxt.Transaction)localObject32).getJSONObject());
                                    ((JSONObject)localObject33).put("transactions", localJSONArray2);
                                    Nxt.Peer.sendToAllPeers((JSONObject)localObject33);
                                    ((JSONObject)localObject1).put("transaction", convert(((Nxt.Transaction)localObject32).getId()));
                                    ((JSONObject)localObject1).put("bytes", convert(((Nxt.Transaction)localObject32).getBytes()));
                                  }
                                }
                                catch (Exception localException19)
                                {
                                  ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                                  ((JSONObject)localObject1).put("errorDescription", "Incorrect \"deadline\"");
                                }
                              }
                              catch (Exception localException20)
                              {
                                ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                                ((JSONObject)localObject1).put("errorDescription", "Incorrect \"fee\"");
                              }
                            }
                            catch (Exception localException21)
                            {
                              ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                              ((JSONObject)localObject1).put("errorDescription", "Incorrect \"amount\"");
                            }
                          }
                          catch (Exception localException22)
                          {
                            ((JSONObject)localObject1).put("errorCode", Integer.valueOf(4));
                            ((JSONObject)localObject1).put("errorDescription", "Incorrect \"recipient\"");
                          }
                          break label7978:
                          ((JSONObject)localObject1).put("errorCode", Integer.valueOf(1));
                          ((JSONObject)localObject1).put("errorDescription", "Incorrect request");
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          paramHttpServletResponse.setContentType("text/plain; charset=UTF-8");
          localObject2 = paramHttpServletResponse.getOutputStream();
          ((ServletOutputStream)localObject2).write(((JSONObject)localObject1).toString().getBytes("UTF-8"));
          ((ServletOutputStream)localObject2).close();
          return;
        }
      }
      if ((allowedUserHosts != null) && (!allowedUserHosts.contains(paramHttpServletRequest.getRemoteHost())))
      {
        localObject1 = new JSONObject();
        ((JSONObject)localObject1).put("response", "denyAccess");
        localObject2 = new JSONArray();
        ((JSONArray)localObject2).add(localObject1);
        localObject4 = new JSONObject();
        ((JSONObject)localObject4).put("responses", localObject2);
        paramHttpServletResponse.setContentType("text/plain; charset=UTF-8");
        localObject5 = paramHttpServletResponse.getOutputStream();
        ((ServletOutputStream)localObject5).write(((JSONObject)localObject4).toString().getBytes("UTF-8"));
        ((ServletOutputStream)localObject5).close();
        return;
      }
      localUser = (Nxt.User)users.get(str1);
      if (localUser == null)
      {
        localUser = new Nxt.User();
        users.put(str1, localUser);
      }
      switch ((localObject1 = paramHttpServletRequest.getParameter("requestType")).hashCode())
      {
      case -1695267198:
        if (((String)localObject1).equals("lockAccount"));
        break;
      case -1413383884:
        if (((String)localObject1).equals("getNewData"));
        break;
      case -1215991508:
        if (((String)localObject1).equals("removeActivePeer"));
        break;
      case -632255711:
        if (((String)localObject1).equals("removeKnownPeer"));
        break;
      case -349483447:
        if (((String)localObject1).equals("unlockAccount"));
        break;
      case 9950744:
        if (((String)localObject1).equals("sendMoney"));
        break;
      case 94341973:
        if (((String)localObject1).equals("generateAuthorizationToken"));
        break;
      case 592625624:
        if (((String)localObject1).equals("getInitialData"));
        break;
      case 892719322:
        Object localObject29;
        Object localObject31;
        Object localObject30;
        int i12;
        if (!((String)localObject1).equals("removeBlacklistedPeer"))
        {
          break label13145:
          localObject2 = paramHttpServletRequest.getParameter("website").trim().getBytes("UTF-8");
          localObject4 = new byte[localObject2.length + 32 + 4];
          System.arraycopy(localObject2, 0, localObject4, 0, localObject2.length);
          System.arraycopy(Nxt.Crypto.getPublicKey(localUser.secretPhrase), 0, localObject4, localObject2.length, 32);
          int l = getEpochTime(System.currentTimeMillis());
          localObject4[(localObject2.length + 32)] = (byte)l;
          localObject4[(localObject2.length + 32 + 1)] = (byte)(l >> 8);
          localObject4[(localObject2.length + 32 + 2)] = (byte)(l >> 16);
          localObject4[(localObject2.length + 32 + 3)] = (byte)(l >> 24);
          localObject9 = new byte[100];
          System.arraycopy(localObject4, localObject2.length, localObject9, 0, 36);
          System.arraycopy(Nxt.Crypto.sign(localObject4, localUser.secretPhrase), 0, localObject9, 36, 64);
          ??? = "";
          for (int i4 = 0; i4 < 100; i4 += 5)
          {
            long l7 = localObject9[i4] & 0xFF | (localObject9[(i4 + 1)] & 0xFF) << 8 | (localObject9[(i4 + 2)] & 0xFF) << 16 | (localObject9[(i4 + 3)] & 0xFF) << 24 | (localObject9[(i4 + 4)] & 0xFF) << 32;
            if (l7 < 32L)
              ??? = ??? + "0000000";
            else if (l7 < 1024L)
              ??? = ??? + "000000";
            else if (l7 < 32768L)
              ??? = ??? + "00000";
            else if (l7 < 1048576L)
              ??? = ??? + "0000";
            else if (l7 < 33554432L)
              ??? = ??? + "000";
            else if (l7 < 1073741824L)
              ??? = ??? + "00";
            else if (l7 < 34359738368L)
              ??? = ??? + "0";
            ??? = ??? + Long.toString(l7, 32);
          }
          JSONObject localJSONObject3 = new JSONObject();
          localJSONObject3.put("response", "showAuthorizationToken");
          localJSONObject3.put("token", ???);
          localUser.pendingResponses.offer(localJSONObject3);
          break label13242:
          localObject2 = new JSONArray();
          localObject4 = new JSONArray();
          localObject6 = new JSONArray();
          localObject9 = new JSONArray();
          ??? = new JSONArray();
          Object localObject17;
          Object localObject24;
          synchronized (transactions)
          {
            localObject21 = unconfirmedTransactions.values().iterator();
            while (((Iterator)localObject21).hasNext())
            {
              localObject17 = (Nxt.Transaction)((Iterator)localObject21).next();
              localObject24 = new JSONObject();
              ((JSONObject)localObject24).put("index", Integer.valueOf(((Nxt.Transaction)localObject17).index));
              ((JSONObject)localObject24).put("timestamp", Integer.valueOf(((Nxt.Transaction)localObject17).timestamp));
              ((JSONObject)localObject24).put("deadline", Short.valueOf(((Nxt.Transaction)localObject17).deadline));
              ((JSONObject)localObject24).put("recipient", convert(((Nxt.Transaction)localObject17).recipient));
              ((JSONObject)localObject24).put("amount", Integer.valueOf(((Nxt.Transaction)localObject17).amount));
              ((JSONObject)localObject24).put("fee", Integer.valueOf(((Nxt.Transaction)localObject17).fee));
              ((JSONObject)localObject24).put("sender", convert(Nxt.Account.getId(((Nxt.Transaction)localObject17).senderPublicKey)));
              ((JSONArray)localObject2).add(localObject24);
            }
          }
          synchronized (peers)
          {
            localObject21 = peers.entrySet().iterator();
            while (((Iterator)localObject21).hasNext())
            {
              localObject17 = (Map.Entry)((Iterator)localObject21).next();
              localObject24 = (String)((Map.Entry)localObject17).getKey();
              localObject26 = (Nxt.Peer)((Map.Entry)localObject17).getValue();
              if (((Nxt.Peer)localObject26).blacklistingTime > 0L)
              {
                localObject29 = new JSONObject();
                ((JSONObject)localObject29).put("index", Integer.valueOf(((Nxt.Peer)localObject26).index));
                ((JSONObject)localObject29).put("announcedAddress", (((Nxt.Peer)localObject26).announcedAddress.length() > 0) ? ((Nxt.Peer)localObject26).announcedAddress : (((Nxt.Peer)localObject26).announcedAddress.length() > 30) ? ((Nxt.Peer)localObject26).announcedAddress.substring(0, 30) + "..." : localObject24);
                localObject31 = wellKnownPeers.iterator();
                while (((Iterator)localObject31).hasNext())
                {
                  localObject30 = (String)((Iterator)localObject31).next();
                  if (!((Nxt.Peer)localObject26).announcedAddress.equals(localObject30))
                    continue;
                  ((JSONObject)localObject29).put("wellKnown", Boolean.valueOf(true));
                  break;
                }
                ((JSONArray)localObject9).add(localObject29);
              }
              else if (((Nxt.Peer)localObject26).state == 0)
              {
                if (((Nxt.Peer)localObject26).announcedAddress.length() <= 0)
                  continue;
                localObject29 = new JSONObject();
                ((JSONObject)localObject29).put("index", Integer.valueOf(((Nxt.Peer)localObject26).index));
                ((JSONObject)localObject29).put("announcedAddress", (((Nxt.Peer)localObject26).announcedAddress.length() > 30) ? ((Nxt.Peer)localObject26).announcedAddress.substring(0, 30) + "..." : ((Nxt.Peer)localObject26).announcedAddress);
                localObject31 = wellKnownPeers.iterator();
                while (((Iterator)localObject31).hasNext())
                {
                  localObject30 = (String)((Iterator)localObject31).next();
                  if (!((Nxt.Peer)localObject26).announcedAddress.equals(localObject30))
                    continue;
                  ((JSONObject)localObject29).put("wellKnown", Boolean.valueOf(true));
                  break;
                }
                ((JSONArray)localObject6).add(localObject29);
              }
              else
              {
                localObject29 = new JSONObject();
                ((JSONObject)localObject29).put("index", Integer.valueOf(((Nxt.Peer)localObject26).index));
                if (((Nxt.Peer)localObject26).state == 2)
                  ((JSONObject)localObject29).put("disconnected", Boolean.valueOf(true));
                ((JSONObject)localObject29).put("address", (((String)localObject24).length() > 30) ? ((String)localObject24).substring(0, 30) + "..." : localObject24);
                ((JSONObject)localObject29).put("announcedAddress", (((Nxt.Peer)localObject26).announcedAddress.length() > 30) ? ((Nxt.Peer)localObject26).announcedAddress.substring(0, 30) + "..." : ((Nxt.Peer)localObject26).announcedAddress);
                ((JSONObject)localObject29).put("weight", Integer.valueOf(((Nxt.Peer)localObject26).getWeight()));
                ((JSONObject)localObject29).put("downloaded", Long.valueOf(((Nxt.Peer)localObject26).downloadedVolume));
                ((JSONObject)localObject29).put("uploaded", Long.valueOf(((Nxt.Peer)localObject26).uploadedVolume));
                ((JSONObject)localObject29).put("software", ((((Nxt.Peer)localObject26).application == null) ? "?" : ((Nxt.Peer)localObject26).application) + " (" + ((((Nxt.Peer)localObject26).version == null) ? "?" : ((Nxt.Peer)localObject26).version) + ")");
                localObject31 = wellKnownPeers.iterator();
                while (((Iterator)localObject31).hasNext())
                {
                  localObject30 = (String)((Iterator)localObject31).next();
                  if (!((Nxt.Peer)localObject26).announcedAddress.equals(localObject30))
                    continue;
                  ((JSONObject)localObject29).put("wellKnown", Boolean.valueOf(true));
                  break;
                }
                ((JSONArray)localObject4).add(localObject29);
              }
            }
          }
          synchronized (blocks)
          {
            long l8 = lastBlock;
            i12 = Nxt.Block.getLastBlock().height;
            int i14 = 0;
            while (i14 < 60)
            {
              ++i14;
              localObject29 = (Nxt.Block)blocks.get(Long.valueOf(l8));
              localObject30 = new JSONObject();
              ((JSONObject)localObject30).put("index", Integer.valueOf(((Nxt.Block)localObject29).index));
              ((JSONObject)localObject30).put("timestamp", Integer.valueOf(((Nxt.Block)localObject29).timestamp));
              ((JSONObject)localObject30).put("numberOfTransactions", Integer.valueOf(((Nxt.Block)localObject29).numberOfTransactions));
              ((JSONObject)localObject30).put("totalAmount", Integer.valueOf(((Nxt.Block)localObject29).totalAmount));
              ((JSONObject)localObject30).put("totalFee", Integer.valueOf(((Nxt.Block)localObject29).totalFee));
              ((JSONObject)localObject30).put("payloadLength", Integer.valueOf(((Nxt.Block)localObject29).payloadLength));
              ((JSONObject)localObject30).put("generator", convert(Nxt.Account.getId(((Nxt.Block)localObject29).generatorPublicKey)));
              ((JSONObject)localObject30).put("height", Integer.valueOf(i12));
              ((JSONObject)localObject30).put("version", Integer.valueOf(((Nxt.Block)localObject29).version));
              ((JSONObject)localObject30).put("block", convert(l8));
              ((JSONObject)localObject30).put("baseTarget", BigInteger.valueOf(((Nxt.Block)localObject29).baseTarget).multiply(BigInteger.valueOf(100000L)).divide(BigInteger.valueOf(153722867L)));
              ((JSONArray)???).add(localObject30);
              if (l8 == 2680262203532249785L)
                break;
              l8 = ((Nxt.Block)localObject29).previousBlock;
              --i12;
            }
          }
          ??? = new JSONObject();
          ((JSONObject)???).put("response", "processInitialData");
          ((JSONObject)???).put("version", "0.4.2");
          if (((JSONArray)localObject2).size() > 0)
            ((JSONObject)???).put("unconfirmedTransactions", localObject2);
          if (((JSONArray)localObject4).size() > 0)
            ((JSONObject)???).put("activePeers", localObject4);
          if (((JSONArray)localObject6).size() > 0)
            ((JSONObject)???).put("knownPeers", localObject6);
          if (((JSONArray)localObject9).size() > 0)
            ((JSONObject)???).put("blacklistedPeers", localObject9);
          if (((JSONArray)???).size() > 0)
            ((JSONObject)???).put("recentBlocks", ???);
          localUser.pendingResponses.offer(???);
          break label13242:
          localUser.deinitializeKeyPair();
          localObject2 = new JSONObject();
          ((JSONObject)localObject2).put("response", "lockAccount");
          localUser.pendingResponses.offer(localObject2);
          break label13242:
          if ((allowedUserHosts == null) && (!InetAddress.getByName(paramHttpServletRequest.getRemoteAddr()).isLoopbackAddress()))
          {
            localObject2 = new JSONObject();
            ((JSONObject)localObject2).put("response", "showMessage");
            ((JSONObject)localObject2).put("message", "This operation is allowed to local host users only!");
            localUser.pendingResponses.offer(localObject2);
          }
          else
          {
            int i = Integer.parseInt(paramHttpServletRequest.getParameter("peer"));
            localObject6 = peers.values().iterator();
            while (((Iterator)localObject6).hasNext())
            {
              localObject4 = (Nxt.Peer)((Iterator)localObject6).next();
              if (((Nxt.Peer)localObject4).index != i)
                continue;
              if ((((Nxt.Peer)localObject4).blacklistingTime == 0L) && (((Nxt.Peer)localObject4).state != 0))
                ((Nxt.Peer)localObject4).deactivate();
            }
          }
        }
        else if ((allowedUserHosts == null) && (!InetAddress.getByName(paramHttpServletRequest.getRemoteAddr()).isLoopbackAddress()))
        {
          JSONObject localJSONObject1 = new JSONObject();
          localJSONObject1.put("response", "showMessage");
          localJSONObject1.put("message", "This operation is allowed to local host users only!");
          localUser.pendingResponses.offer(localJSONObject1);
        }
        else
        {
          int j = Integer.parseInt(paramHttpServletRequest.getParameter("peer"));
          localObject6 = peers.values().iterator();
          while (((Iterator)localObject6).hasNext())
          {
            localObject4 = (Nxt.Peer)((Iterator)localObject6).next();
            if (((Nxt.Peer)localObject4).index != j)
              continue;
            if (((Nxt.Peer)localObject4).blacklistingTime > 0L)
              ((Nxt.Peer)localObject4).removeBlacklistedStatus();
          }
          break label13242:
          if ((allowedUserHosts == null) && (!InetAddress.getByName(paramHttpServletRequest.getRemoteAddr()).isLoopbackAddress()))
          {
            JSONObject localJSONObject2 = new JSONObject();
            localJSONObject2.put("response", "showMessage");
            localJSONObject2.put("message", "This operation is allowed to local host users only!");
            localUser.pendingResponses.offer(localJSONObject2);
          }
          else
          {
            int k = Integer.parseInt(paramHttpServletRequest.getParameter("peer"));
            localObject6 = peers.values().iterator();
            while (((Iterator)localObject6).hasNext())
            {
              localObject4 = (Nxt.Peer)((Iterator)localObject6).next();
              if (((Nxt.Peer)localObject4).index != k)
                continue;
              ((Nxt.Peer)localObject4).removePeer();
              break label13242:
            }
            break label13242:
            if (localUser.secretPhrase != null)
            {
              localObject3 = paramHttpServletRequest.getParameter("recipient");
              localObject4 = paramHttpServletRequest.getParameter("amount");
              localObject6 = paramHttpServletRequest.getParameter("fee");
              localObject9 = paramHttpServletRequest.getParameter("deadline");
              int i7 = 0;
              int i10 = 0;
              i12 = 0;
              long l5;
              Object localObject27;
              try
              {
                l5 = new BigInteger(((String)localObject3).trim()).longValue();
                i7 = Integer.parseInt(((String)localObject4).trim());
                i10 = Integer.parseInt(((String)localObject6).trim());
                i12 = (short)(int)(Double.parseDouble((String)localObject9) * 60.0D);
              }
              catch (Exception localException23)
              {
                localObject27 = new JSONObject();
                ((JSONObject)localObject27).put("response", "notifyOfIncorrectTransaction");
                ((JSONObject)localObject27).put("message", "One of the fields is filled incorrectly!");
                ((JSONObject)localObject27).put("recipient", localObject3);
                ((JSONObject)localObject27).put("amount", localObject4);
                ((JSONObject)localObject27).put("fee", localObject6);
                ((JSONObject)localObject27).put("deadline", localObject9);
                localUser.pendingResponses.offer(localObject27);
                break label13242:
              }
              if (i7 <= 0)
              {
                localObject27 = new JSONObject();
                ((JSONObject)localObject27).put("response", "notifyOfIncorrectTransaction");
                ((JSONObject)localObject27).put("message", "\"Amount\" must be greater than 0!");
                ((JSONObject)localObject27).put("recipient", localObject3);
                ((JSONObject)localObject27).put("amount", localObject4);
                ((JSONObject)localObject27).put("fee", localObject6);
                ((JSONObject)localObject27).put("deadline", localObject9);
                localUser.pendingResponses.offer(localObject27);
              }
              else if (i10 <= 0)
              {
                localObject27 = new JSONObject();
                ((JSONObject)localObject27).put("response", "notifyOfIncorrectTransaction");
                ((JSONObject)localObject27).put("message", "\"Fee\" must be greater than 0!");
                ((JSONObject)localObject27).put("recipient", localObject3);
                ((JSONObject)localObject27).put("amount", localObject4);
                ((JSONObject)localObject27).put("fee", localObject6);
                ((JSONObject)localObject27).put("deadline", localObject9);
                localUser.pendingResponses.offer(localObject27);
              }
              else if (i12 < 1)
              {
                localObject27 = new JSONObject();
                ((JSONObject)localObject27).put("response", "notifyOfIncorrectTransaction");
                ((JSONObject)localObject27).put("message", "\"Deadline\" must be greater or equal to 1 minute!");
                ((JSONObject)localObject27).put("recipient", localObject3);
                ((JSONObject)localObject27).put("amount", localObject4);
                ((JSONObject)localObject27).put("fee", localObject6);
                ((JSONObject)localObject27).put("deadline", localObject9);
                localUser.pendingResponses.offer(localObject27);
              }
              else
              {
                localObject27 = Nxt.Crypto.getPublicKey(localUser.secretPhrase);
                localObject29 = (Nxt.Account)accounts.get(Long.valueOf(Nxt.Account.getId(localObject27)));
                if ((localObject29 == null) || ((i7 + i10) * 100L > ((Nxt.Account)localObject29).unconfirmedBalance))
                {
                  localObject30 = new JSONObject();
                  ((JSONObject)localObject30).put("response", "notifyOfIncorrectTransaction");
                  ((JSONObject)localObject30).put("message", "Not enough funds!");
                  ((JSONObject)localObject30).put("recipient", localObject3);
                  ((JSONObject)localObject30).put("amount", localObject4);
                  ((JSONObject)localObject30).put("fee", localObject6);
                  ((JSONObject)localObject30).put("deadline", localObject9);
                  localUser.pendingResponses.offer(localObject30);
                }
                else
                {
                  localObject30 = new Nxt.Transaction(0, 0, getEpochTime(System.currentTimeMillis()), i12, localObject27, l5, i7, i10, 0L, new byte[64]);
                  ((Nxt.Transaction)localObject30).sign(localUser.secretPhrase);
                  localObject31 = new JSONObject();
                  ((JSONObject)localObject31).put("requestType", "processTransactions");
                  JSONArray localJSONArray1 = new JSONArray();
                  localJSONArray1.add(((Nxt.Transaction)localObject30).getJSONObject());
                  ((JSONObject)localObject31).put("transactions", localJSONArray1);
                  Nxt.Peer.sendToAllPeers((JSONObject)localObject31);
                  JSONObject localJSONObject4 = new JSONObject();
                  localJSONObject4.put("response", "notifyOfAcceptedTransaction");
                  localUser.pendingResponses.offer(localJSONObject4);
                  break label13242:
                  localObject3 = paramHttpServletRequest.getParameter("secretPhrase");
                  localObject4 = localUser.initializeKeyPair((String)localObject3);
                  localObject6 = new JSONObject();
                  ((JSONObject)localObject6).put("response", "unlockAccount");
                  ((JSONObject)localObject6).put("account", ((BigInteger)localObject4).toString());
                  if (((String)localObject3).length() < 30)
                    ((JSONObject)localObject6).put("secretPhraseStrength", Integer.valueOf(1));
                  else
                    ((JSONObject)localObject6).put("secretPhraseStrength", Integer.valueOf(5));
                  localObject9 = (Nxt.Account)accounts.get(Long.valueOf(((BigInteger)localObject4).longValue()));
                  if (localObject9 == null)
                  {
                    ((JSONObject)localObject6).put("balance", Integer.valueOf(0));
                  }
                  else
                  {
                    ((JSONObject)localObject6).put("balance", Long.valueOf(((Nxt.Account)localObject9).unconfirmedBalance));
                    Object localObject18;
                    Object localObject22;
                    Object localObject25;
                    if (((Nxt.Account)localObject9).getEffectiveBalance() > 0)
                    {
                      localObject11 = new JSONObject();
                      ((JSONObject)localObject11).put("response", "setBlockGenerationDeadline");
                      ??? = Nxt.Block.getLastBlock();
                      localObject18 = Nxt.Crypto.sign(((Nxt.Block)???).generationSignature, localUser.secretPhrase);
                      localObject22 = MessageDigest.getInstance("SHA-256").digest(localObject18);
                      localObject25 = new BigInteger(1, new byte[] { localObject22[7], localObject22[6], localObject22[5], localObject22[4], localObject22[3], localObject22[2], localObject22[1], localObject22[0] });
                      ((JSONObject)localObject11).put("deadline", Long.valueOf(((BigInteger)localObject25).divide(BigInteger.valueOf(Nxt.Block.getBaseTarget()).multiply(BigInteger.valueOf(((Nxt.Account)localObject9).getEffectiveBalance()))).longValue() - (getEpochTime(System.currentTimeMillis()) - ((Nxt.Block)???).timestamp)));
                      localUser.pendingResponses.offer(localObject11);
                    }
                    Object localObject11 = new JSONArray();
                    synchronized (transactions)
                    {
                      localObject22 = unconfirmedTransactions.values().iterator();
                      while (((Iterator)localObject22).hasNext())
                      {
                        localObject18 = (Nxt.Transaction)((Iterator)localObject22).next();
                        if (Nxt.Account.getId(((Nxt.Transaction)localObject18).senderPublicKey) == ((BigInteger)localObject4).longValue())
                        {
                          localObject25 = new JSONObject();
                          ((JSONObject)localObject25).put("index", Integer.valueOf(((Nxt.Transaction)localObject18).index));
                          ((JSONObject)localObject25).put("transactionTimestamp", Integer.valueOf(((Nxt.Transaction)localObject18).timestamp));
                          ((JSONObject)localObject25).put("deadline", Short.valueOf(((Nxt.Transaction)localObject18).deadline));
                          ((JSONObject)localObject25).put("account", convert(((Nxt.Transaction)localObject18).recipient));
                          ((JSONObject)localObject25).put("sentAmount", Integer.valueOf(((Nxt.Transaction)localObject18).amount));
                          if (((Nxt.Transaction)localObject18).recipient == ((BigInteger)localObject4).longValue())
                            ((JSONObject)localObject25).put("receivedAmount", Integer.valueOf(((Nxt.Transaction)localObject18).amount));
                          ((JSONObject)localObject25).put("fee", Integer.valueOf(((Nxt.Transaction)localObject18).fee));
                          ((JSONObject)localObject25).put("numberOfConfirmations", Integer.valueOf(0));
                          ((JSONObject)localObject25).put("id", convert(((Nxt.Transaction)localObject18).getId()));
                          ((JSONArray)localObject11).add(localObject25);
                        }
                        else
                        {
                          if (((Nxt.Transaction)localObject18).recipient != ((BigInteger)localObject4).longValue())
                            continue;
                          localObject25 = new JSONObject();
                          ((JSONObject)localObject25).put("index", Integer.valueOf(((Nxt.Transaction)localObject18).index));
                          ((JSONObject)localObject25).put("transactionTimestamp", Integer.valueOf(((Nxt.Transaction)localObject18).timestamp));
                          ((JSONObject)localObject25).put("deadline", Short.valueOf(((Nxt.Transaction)localObject18).deadline));
                          ((JSONObject)localObject25).put("account", convert(Nxt.Account.getId(((Nxt.Transaction)localObject18).senderPublicKey)));
                          ((JSONObject)localObject25).put("receivedAmount", Integer.valueOf(((Nxt.Transaction)localObject18).amount));
                          ((JSONObject)localObject25).put("fee", Integer.valueOf(((Nxt.Transaction)localObject18).fee));
                          ((JSONObject)localObject25).put("numberOfConfirmations", Integer.valueOf(0));
                          ((JSONObject)localObject25).put("id", convert(((Nxt.Transaction)localObject18).getId()));
                          ((JSONArray)localObject11).add(localObject25);
                        }
                      }
                    }
                    long l6 = lastBlock;
                    for (int i11 = 1; ((JSONArray)localObject11).size() < 1000; ++i11)
                    {
                      localObject25 = (Nxt.Block)blocks.get(Long.valueOf(l6));
                      if ((Nxt.Account.getId(((Nxt.Block)localObject25).generatorPublicKey) == ((BigInteger)localObject4).longValue()) && (((Nxt.Block)localObject25).totalFee > 0))
                      {
                        localObject27 = new JSONObject();
                        ((JSONObject)localObject27).put("index", convert(l6));
                        ((JSONObject)localObject27).put("blockTimestamp", Integer.valueOf(((Nxt.Block)localObject25).timestamp));
                        ((JSONObject)localObject27).put("block", convert(l6));
                        ((JSONObject)localObject27).put("earnedAmount", Integer.valueOf(((Nxt.Block)localObject25).totalFee));
                        ((JSONObject)localObject27).put("numberOfConfirmations", Integer.valueOf(i11));
                        ((JSONObject)localObject27).put("id", "-");
                        ((JSONArray)localObject11).add(localObject27);
                      }
                      for (int i15 = 0; i15 < ((Nxt.Block)localObject25).transactions.length; ++i15)
                      {
                        localObject29 = (Nxt.Transaction)transactions.get(Long.valueOf(localObject25.transactions[i15]));
                        if (Nxt.Account.getId(((Nxt.Transaction)localObject29).senderPublicKey) == ((BigInteger)localObject4).longValue())
                        {
                          localObject30 = new JSONObject();
                          ((JSONObject)localObject30).put("index", Integer.valueOf(((Nxt.Transaction)localObject29).index));
                          ((JSONObject)localObject30).put("blockTimestamp", Integer.valueOf(((Nxt.Block)localObject25).timestamp));
                          ((JSONObject)localObject30).put("transactionTimestamp", Integer.valueOf(((Nxt.Transaction)localObject29).timestamp));
                          ((JSONObject)localObject30).put("account", convert(((Nxt.Transaction)localObject29).recipient));
                          ((JSONObject)localObject30).put("sentAmount", Integer.valueOf(((Nxt.Transaction)localObject29).amount));
                          if (((Nxt.Transaction)localObject29).recipient == ((BigInteger)localObject4).longValue())
                            ((JSONObject)localObject30).put("receivedAmount", Integer.valueOf(((Nxt.Transaction)localObject29).amount));
                          ((JSONObject)localObject30).put("fee", Integer.valueOf(((Nxt.Transaction)localObject29).fee));
                          ((JSONObject)localObject30).put("numberOfConfirmations", Integer.valueOf(i11));
                          ((JSONObject)localObject30).put("id", convert(((Nxt.Transaction)localObject29).getId()));
                          ((JSONArray)localObject11).add(localObject30);
                        }
                        else
                        {
                          if (((Nxt.Transaction)localObject29).recipient != ((BigInteger)localObject4).longValue())
                            continue;
                          localObject30 = new JSONObject();
                          ((JSONObject)localObject30).put("index", Integer.valueOf(((Nxt.Transaction)localObject29).index));
                          ((JSONObject)localObject30).put("blockTimestamp", Integer.valueOf(((Nxt.Block)localObject25).timestamp));
                          ((JSONObject)localObject30).put("transactionTimestamp", Integer.valueOf(((Nxt.Transaction)localObject29).timestamp));
                          ((JSONObject)localObject30).put("account", convert(Nxt.Account.getId(((Nxt.Transaction)localObject29).senderPublicKey)));
                          ((JSONObject)localObject30).put("receivedAmount", Integer.valueOf(((Nxt.Transaction)localObject29).amount));
                          ((JSONObject)localObject30).put("fee", Integer.valueOf(((Nxt.Transaction)localObject29).fee));
                          ((JSONObject)localObject30).put("numberOfConfirmations", Integer.valueOf(i11));
                          ((JSONObject)localObject30).put("id", convert(((Nxt.Transaction)localObject29).getId()));
                          ((JSONArray)localObject11).add(localObject30);
                        }
                      }
                      if (l6 == 2680262203532249785L)
                        break;
                      l6 = ((Nxt.Block)localObject25).previousBlock;
                    }
                    if (((JSONArray)localObject11).size() > 0)
                    {
                      localObject25 = new JSONObject();
                      ((JSONObject)localObject25).put("response", "processNewData");
                      ((JSONObject)localObject25).put("addedMyTransactions", localObject11);
                      localUser.pendingResponses.offer(localObject25);
                    }
                  }
                  localUser.pendingResponses.offer(localObject6);
                }
              }
            }
          }
        }
        break;
      default:
        label13145: localObject3 = new JSONObject();
        ((JSONObject)localObject3).put("response", "showMessage");
        ((JSONObject)localObject3).put("message", "Incorrect request!");
        localUser.pendingResponses.offer(localObject3);
      }
    }
    catch (Exception localException1)
    {
      if (localUser != null)
      {
        localObject1 = new JSONObject();
        ((JSONObject)localObject1).put("response", "showMessage");
        ((JSONObject)localObject1).put("message", localException1.toString());
        localUser.pendingResponses.offer(localObject1);
      }
    }
    if (localUser == null)
      label13242: return;
    synchronized (localUser)
    {
      localObject1 = new JSONArray();
      while ((localObject3 = (JSONObject)localUser.pendingResponses.poll()) != null)
        ((JSONArray)localObject1).add(localObject3);
      if (((JSONArray)localObject1).size() > 0)
      {
        localObject4 = new JSONObject();
        ((JSONObject)localObject4).put("responses", localObject1);
        if (localUser.asyncContext != null)
        {
          localUser.asyncContext.getResponse().setContentType("text/plain; charset=UTF-8");
          localObject6 = localUser.asyncContext.getResponse().getOutputStream();
          ((ServletOutputStream)localObject6).write(((JSONObject)localObject4).toString().getBytes("UTF-8"));
          ((ServletOutputStream)localObject6).close();
          localUser.asyncContext.complete();
          localUser.asyncContext = paramHttpServletRequest.startAsync();
          localUser.asyncContext.addListener(new Nxt.UserAsyncListener(localUser));
          localUser.asyncContext.setTimeout(5000L);
        }
        else
        {
          paramHttpServletResponse.setContentType("text/plain; charset=UTF-8");
          localObject6 = paramHttpServletResponse.getOutputStream();
          ((ServletOutputStream)localObject6).write(((JSONObject)localObject4).toString().getBytes("UTF-8"));
          ((ServletOutputStream)localObject6).close();
        }
      }
      else
      {
        if (localUser.asyncContext != null)
        {
          localUser.asyncContext.getResponse().setContentType("text/plain; charset=UTF-8");
          localObject4 = localUser.asyncContext.getResponse().getOutputStream();
          ((ServletOutputStream)localObject4).write(new JSONObject().toString().getBytes("UTF-8"));
          ((ServletOutputStream)localObject4).close();
          localUser.asyncContext.complete();
        }
        localUser.asyncContext = paramHttpServletRequest.startAsync();
        localUser.asyncContext.addListener(new Nxt.UserAsyncListener(localUser));
        localUser.asyncContext.setTimeout(5000L);
      }
    }
  }

  public void doPost(HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse)
    throws ServletException, IOException
  {
    Nxt.Peer localPeer = null;
    JSONObject localJSONObject1 = new JSONObject();
    try
    {
      localObject1 = paramHttpServletRequest.getInputStream();
      Object localObject2 = new ByteArrayOutputStream();
      Object localObject3 = new byte[65536];
      int l;
      while ((l = ((InputStream)localObject1).read(localObject3)) > 0)
        ((ByteArrayOutputStream)localObject2).write(localObject3, 0, l);
      ((InputStream)localObject1).close();
      JSONObject localJSONObject2 = (JSONObject)JSONValue.parse(((ByteArrayOutputStream)localObject2).toString("UTF-8"));
      localPeer = Nxt.Peer.addPeer(paramHttpServletRequest.getRemoteHost(), "");
      if (localPeer != null)
      {
        if (localPeer.state == 2)
          localPeer.setState(1);
        localPeer.updateDownloadedVolume(((ByteArrayOutputStream)localObject2).size());
      }
      if (((Long)localJSONObject2.get("protocol")).longValue() == 1L);
      switch ((localObject1 = (String)localJSONObject2.get("requestType")).hashCode())
      {
      case -2055947697:
        if (((String)localObject1).equals("getNextBlocks"));
        break;
      case -1195538491:
        if (((String)localObject1).equals("getMilestoneBlockIds"));
        break;
      case -80817804:
        if (((String)localObject1).equals("getNextBlockIds"));
        break;
      case -75444956:
        if (((String)localObject1).equals("getInfo"));
        break;
      case 382446885:
        if (((String)localObject1).equals("getUnconfirmedTransactions"));
        break;
      case 1172622692:
        if (((String)localObject1).equals("processTransactions"));
        break;
      case 1608811908:
        if (((String)localObject1).equals("getCumulativeDifficulty"));
        break;
      case 1962369435:
        if (((String)localObject1).equals("getPeers"));
        break;
      case 1966367582:
        int i3;
        int i;
        if (!((String)localObject1).equals("processBlock"))
        {
          break label1601:
          localJSONObject1.put("cumulativeDifficulty", Nxt.Block.getLastBlock().cumulativeDifficulty.toString());
          break label1647:
          localObject2 = (String)localJSONObject2.get("announcedAddress");
          if (localObject2 != null)
          {
            localObject2 = ((String)localObject2).trim();
            if (((String)localObject2).length() > 0)
              localPeer.announcedAddress = ((String)localObject2);
          }
          if (localPeer != null)
          {
            localObject3 = (String)localJSONObject2.get("application");
            if (localObject3 == null)
            {
              localObject3 = "?";
            }
            else
            {
              localObject3 = ((String)localObject3).trim();
              if (((String)localObject3).length() > 20)
                localObject3 = ((String)localObject3).substring(0, 20) + "...";
            }
            localPeer.application = ((String)localObject3);
            String str = (String)localJSONObject2.get("version");
            if (str == null)
            {
              str = "?";
            }
            else
            {
              str = str.trim();
              if (str.length() > 10)
                str = str.substring(0, 10) + "...";
            }
            localPeer.version = str;
            if (localPeer.analyzeHallmark(paramHttpServletRequest.getRemoteHost(), (String)localJSONObject2.get("hallmark")))
              localPeer.setState(1);
            else
              localPeer.blacklist();
          }
          if ((myHallmark != null) && (myHallmark.length() > 0))
            localJSONObject1.put("hallmark", myHallmark);
          localJSONObject1.put("application", "NRS");
          localJSONObject1.put("version", "0.4.2");
          break label1647:
          localObject2 = new JSONArray();
          localObject3 = Nxt.Block.getLastBlock();
          int i1 = ((Nxt.Block)localObject3).height * 4 / 1461 + 1;
          int i2;
          while (((Nxt.Block)localObject3).height > 0)
          {
            ((JSONArray)localObject2).add(convert(((Nxt.Block)localObject3).getId()));
            for (i2 = 0; (i2 < i1) && (((Nxt.Block)localObject3).height > 0); ++i2)
              localObject3 = (Nxt.Block)blocks.get(Long.valueOf(((Nxt.Block)localObject3).previousBlock));
          }
          localJSONObject1.put("milestoneBlockIds", localObject2);
          break label1647:
          localObject2 = new JSONArray();
          localObject3 = (Nxt.Block)blocks.get(Long.valueOf(new BigInteger((String)localJSONObject2.get("blockId")).longValue()));
          while ((localObject3 != null) && (((JSONArray)localObject2).size() < 1440))
          {
            localObject3 = (Nxt.Block)blocks.get(Long.valueOf(((Nxt.Block)localObject3).nextBlock));
            if (localObject3 == null)
              continue;
            ((JSONArray)localObject2).add(convert(((Nxt.Block)localObject3).getId()));
          }
          localJSONObject1.put("nextBlockIds", localObject2);
          break label1647:
          localObject2 = new LinkedList();
          int j = 0;
          Object localObject5 = (Nxt.Block)blocks.get(Long.valueOf(new BigInteger((String)localJSONObject2.get("blockId")).longValue()));
          while (localObject5 != null)
          {
            localObject5 = (Nxt.Block)blocks.get(Long.valueOf(((Nxt.Block)localObject5).nextBlock));
            if (localObject5 == null)
              continue;
            i2 = 224 + ((Nxt.Block)localObject5).payloadLength;
            if (j + i2 > 131072)
              break;
            ((LinkedList)localObject2).add(localObject5);
            j += i2;
          }
          Object localObject6 = new JSONArray();
          for (i3 = 0; i3 < ((LinkedList)localObject2).size(); ++i3)
            ((JSONArray)localObject6).add(((Nxt.Block)((LinkedList)localObject2).get(i3)).getJSONObject(transactions));
          localJSONObject1.put("nextBlocks", localObject6);
          break label1647:
          localObject2 = new JSONArray();
          localObject5 = peers.values().iterator();
          while (((Iterator)localObject5).hasNext())
          {
            localObject4 = (Nxt.Peer)((Iterator)localObject5).next();
            if ((((Nxt.Peer)localObject4).blacklistingTime != 0L) || (((Nxt.Peer)localObject4).announcedAddress.length() <= 0))
              continue;
            ((JSONArray)localObject2).add(((Nxt.Peer)localObject4).announcedAddress);
          }
          localJSONObject1.put("peers", localObject2);
          break label1647:
          i = 0;
          Object localObject4 = new JSONArray();
          localObject6 = unconfirmedTransactions.values().iterator();
          while (((Iterator)localObject6).hasNext())
          {
            localObject5 = (Nxt.Transaction)((Iterator)localObject6).next();
            ((JSONArray)localObject4).add(((Nxt.Transaction)localObject5).getJSONObject());
            if (++i >= 255)
              break;
          }
          localJSONObject1.put("unconfirmedTransactions", localObject4);
        }
        else
        {
          i = ((Long)localJSONObject2.get("version")).intValue();
          int k = ((Long)localJSONObject2.get("timestamp")).intValue();
          long l1 = new BigInteger((String)localJSONObject2.get("previousBlock")).longValue();
          i3 = ((Long)localJSONObject2.get("numberOfTransactions")).intValue();
          int i4 = ((Long)localJSONObject2.get("totalAmount")).intValue();
          int i5 = ((Long)localJSONObject2.get("totalFee")).intValue();
          int i6 = ((Long)localJSONObject2.get("payloadLength")).intValue();
          byte[] arrayOfByte2 = convert((String)localJSONObject2.get("payloadHash"));
          byte[] arrayOfByte3 = convert((String)localJSONObject2.get("generatorPublicKey"));
          byte[] arrayOfByte4 = convert((String)localJSONObject2.get("generationSignature"));
          byte[] arrayOfByte5 = convert((String)localJSONObject2.get("blockSignature"));
          Nxt.Block localBlock = new Nxt.Block(i, k, l1, i3, i4, i5, i6, arrayOfByte2, arrayOfByte3, arrayOfByte4, arrayOfByte5);
          ByteBuffer localByteBuffer = ByteBuffer.allocate(224 + i6);
          localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
          localByteBuffer.put(localBlock.getBytes());
          JSONArray localJSONArray = (JSONArray)localJSONObject2.get("transactions");
          for (int i7 = 0; i7 < localJSONArray.size(); ++i7)
            localByteBuffer.put(Nxt.Transaction.getTransaction((JSONObject)localJSONArray.get(i7)).getBytes());
          boolean bool = Nxt.Block.pushBlock(localByteBuffer, true);
          localJSONObject1.put("accepted", Boolean.valueOf(bool));
          break label1647:
          Nxt.Transaction.processTransactions(localJSONObject2, "transactions");
        }
        break;
      default:
        label1601: localJSONObject1.put("error", "Unsupported request type!");
        break label1647:
        localJSONObject1.put("error", "Unsupported protocol!");
      }
    }
    catch (Exception localException)
    {
      localJSONObject1.put("error", localException.toString());
    }
    label1647: paramHttpServletResponse.setContentType("text/plain; charset=UTF-8");
    byte[] arrayOfByte1 = localJSONObject1.toString().getBytes("UTF-8");
    Object localObject1 = paramHttpServletResponse.getOutputStream();
    ((ServletOutputStream)localObject1).write(arrayOfByte1);
    ((ServletOutputStream)localObject1).close();
    if (localPeer == null)
      return;
    localPeer.updateUploadedVolume(arrayOfByte1.length);
  }

  public void destroy()
  {
    scheduledThreadPool.shutdown();
    cachedThreadPool.shutdown();
    try
    {
      Nxt.Block.saveBlocks("blocks.nxt", true);
    }
    catch (Exception localException1)
    {
    }
    try
    {
      Nxt.Transaction.saveTransactions("transactions.nxt");
    }
    catch (Exception localException2)
    {
    }
    try
    {
      blockchainChannel.close();
    }
    catch (Exception localException3)
    {
    }
    logMessage("Nxt stopped.");
  }

  static class Account
  {
    long id;
    long balance;
    int height;
    byte[] publicKey;
    HashMap<Long, Integer> assetBalances;
    long unconfirmedBalance;
    HashMap<Long, Integer> unconfirmedAssetBalances;

    Account(long paramLong)
    {
      this.id = paramLong;
      this.height = Nxt.Block.getLastBlock().height;
      this.assetBalances = new HashMap();
      this.unconfirmedAssetBalances = new HashMap();
    }

    static Account addAccount(long paramLong)
    {
      synchronized (Nxt.accounts)
      {
        Account localAccount = new Account(paramLong);
        Nxt.accounts.put(Long.valueOf(paramLong), localAccount);
        return localAccount;
      }
    }

    void generateBlock(String paramString)
      throws Exception
    {
      Object localObject1;
      synchronized (Nxt.transactions)
      {
        localObject1 = (Nxt.Transaction[])Nxt.unconfirmedTransactions.values().toArray(new Nxt.Transaction[0]);
        while (localObject1.length > 0)
        {
          for (int i = 0; i < localObject1.length; ++i)
          {
            localHashMap = localObject1[i];
            if ((localHashMap.referencedTransaction == 0L) || (Nxt.transactions.get(Long.valueOf(localHashMap.referencedTransaction)) != null))
              continue;
            localObject1[i] = localObject1[(localObject1.length - 1)];
            Nxt.Transaction[] arrayOfTransaction = new Nxt.Transaction[localObject1.length - 1];
            System.arraycopy(localObject1, 0, arrayOfTransaction, 0, arrayOfTransaction.length);
            localObject1 = arrayOfTransaction;
            break;
          }
          if (i == localObject1.length)
            break;
        }
      }
      Arrays.sort(localObject1);
      ??? = new HashMap();
      HashSet localHashSet = new HashSet();
      HashMap localHashMap = new HashMap();
      int j = 0;
      while (j <= 32640)
      {
        int k = ((HashMap)???).size();
        for (l = 0; l < localObject1.length; ++l)
        {
          localObject2 = localObject1[l];
          int i1 = ((Nxt.Transaction)localObject2).getBytes().length;
          if ((((HashMap)???).get(Long.valueOf(((Nxt.Transaction)localObject2).getId())) != null) || (j + i1 > 32640))
            continue;
          long l1 = getId(((Nxt.Transaction)localObject2).senderPublicKey);
          Long localLong = (Long)localHashMap.get(Long.valueOf(l1));
          if (localLong == null)
            localLong = new Long(0L);
          long l2 = (((Nxt.Transaction)localObject2).amount + ((Nxt.Transaction)localObject2).fee) * 100L;
          if ((localLong.longValue() + l2 > ((Account)Nxt.accounts.get(Long.valueOf(l1))).balance) || (!((Nxt.Transaction)localObject2).validateAttachment()))
            continue;
          switch (((Nxt.Transaction)localObject2).type)
          {
          case 1:
            switch (((Nxt.Transaction)localObject2).subtype)
            {
            case 1:
              if (!localHashSet.add(((Nxt.Transaction.MessagingAliasAssignmentAttachment)((Nxt.Transaction)localObject2).attachment).alias.toLowerCase()))
                continue;
            }
          }
          localHashMap.put(Long.valueOf(l1), Long.valueOf(localLong.longValue() + l2));
          ((HashMap)???).put(Long.valueOf(((Nxt.Transaction)localObject2).getId()), localObject2);
          j += i1;
        }
        if (((HashMap)???).size() == k)
          break;
      }
      Nxt.Block localBlock = new Nxt.Block(1, Nxt.getEpochTime(System.currentTimeMillis()), Nxt.lastBlock, ((HashMap)???).size(), 0, 0, 0, null, Nxt.Crypto.getPublicKey(paramString), null, new byte[64]);
      localBlock.transactions = new long[localBlock.numberOfTransactions];
      int l = 0;
      Object localObject3 = ((HashMap)???).entrySet().iterator();
      while (((Iterator)localObject3).hasNext())
      {
        localObject2 = (Map.Entry)((Iterator)localObject3).next();
        localObject4 = (Nxt.Transaction)((Map.Entry)localObject2).getValue();
        localBlock.totalAmount += ((Nxt.Transaction)localObject4).amount;
        localBlock.totalFee += ((Nxt.Transaction)localObject4).fee;
        localBlock.payloadLength += ((Nxt.Transaction)localObject4).getBytes().length;
        localBlock.transactions[(l++)] = ((Long)((Map.Entry)localObject2).getKey()).longValue();
      }
      Arrays.sort(localBlock.transactions);
      Object localObject2 = MessageDigest.getInstance("SHA-256");
      for (l = 0; l < localBlock.numberOfTransactions; ++l)
        ((MessageDigest)localObject2).update(((Nxt.Transaction)((HashMap)???).get(Long.valueOf(localBlock.transactions[l]))).getBytes());
      localBlock.payloadHash = ((MessageDigest)localObject2).digest();
      localBlock.generationSignature = Nxt.Crypto.sign(Nxt.Block.getLastBlock().generationSignature, paramString);
      localObject3 = localBlock.getBytes();
      Object localObject4 = new byte[localObject3.length - 64];
      System.arraycopy(localObject3, 0, localObject4, 0, localObject4.length);
      localBlock.blockSignature = Nxt.Crypto.sign(localObject4, paramString);
      JSONObject localJSONObject = localBlock.getJSONObject((HashMap)???);
      localJSONObject.put("requestType", "processBlock");
      if ((localBlock.verifyBlockSignature()) && (localBlock.verifyGenerationSignature()))
        Nxt.Peer.sendToAllPeers(localJSONObject);
      else
        Nxt.logMessage("Generated an incorrect block. Waiting for the next one...");
    }

    int getEffectiveBalance()
    {
      if (this.height == 0)
        return (int)(this.balance / 100L);
      if (Nxt.Block.getLastBlock().height - this.height < 1440)
        return 0;
      int i = 0;
      for (long l : Nxt.Block.getLastBlock().transactions)
      {
        Nxt.Transaction localTransaction = (Nxt.Transaction)Nxt.transactions.get(Long.valueOf(l));
        if (localTransaction.recipient != this.id)
          continue;
        i += localTransaction.amount;
      }
      return (int)(this.balance / 100L) - i;
    }

    static long getId(byte[] paramArrayOfByte)
      throws Exception
    {
      byte[] arrayOfByte = MessageDigest.getInstance("SHA-256").digest(paramArrayOfByte);
      BigInteger localBigInteger = new BigInteger(1, new byte[] { arrayOfByte[7], arrayOfByte[6], arrayOfByte[5], arrayOfByte[4], arrayOfByte[3], arrayOfByte[2], arrayOfByte[1], arrayOfByte[0] });
      return localBigInteger.longValue();
    }

    void setBalance(long paramLong)
      throws Exception
    {
      this.balance = paramLong;
      Iterator localIterator = Nxt.peers.values().iterator();
      while (localIterator.hasNext())
      {
        Nxt.Peer localPeer = (Nxt.Peer)localIterator.next();
        if ((localPeer.accountId != this.id) || (localPeer.adjustedWeight <= 0L))
          continue;
        localPeer.updateWeight();
      }
    }

    void setUnconfirmedBalance(long paramLong)
      throws Exception
    {
      this.unconfirmedBalance = paramLong;
      JSONObject localJSONObject = new JSONObject();
      localJSONObject.put("response", "setBalance");
      localJSONObject.put("balance", Long.valueOf(paramLong));
      Iterator localIterator = Nxt.users.values().iterator();
      while (localIterator.hasNext())
      {
        Nxt.User localUser = (Nxt.User)localIterator.next();
        if ((localUser.secretPhrase == null) || (getId(Nxt.Crypto.getPublicKey(localUser.secretPhrase)) != this.id))
          continue;
        localUser.send(localJSONObject);
      }
    }
  }

  static class Alias
  {
    Nxt.Account account;
    String alias;
    String uri;
    int timestamp;

    Alias(Nxt.Account paramAccount, String paramString1, String paramString2, int paramInt)
    {
      this.account = paramAccount;
      this.alias = paramString1;
      this.uri = paramString2;
      this.timestamp = paramInt;
    }
  }

  static class AskOrder
    implements Comparable<AskOrder>
  {
    long id;
    long height;
    Nxt.Account account;
    long asset;
    int quantity;
    long price;

    AskOrder(long paramLong1, Nxt.Account paramAccount, long paramLong2, int paramInt, long paramLong3)
    {
      this.id = paramLong1;
      this.height = Nxt.Block.getLastBlock().height;
      this.account = paramAccount;
      this.asset = paramLong2;
      this.quantity = paramInt;
      this.price = paramLong3;
    }

    public int compareTo(AskOrder paramAskOrder)
    {
      if (this.price < paramAskOrder.price)
        return -1;
      if (this.price > paramAskOrder.price)
        return 1;
      if (this.height < paramAskOrder.height)
        return -1;
      if (this.height > paramAskOrder.height)
        return 1;
      if (this.id < paramAskOrder.id)
        return -1;
      if (this.id > paramAskOrder.id)
        return 1;
      return 0;
    }
  }

  static class Asset
  {
    long accountId;
    String name;
    String description;
    int quantity;

    Asset(long paramLong, String paramString1, String paramString2, int paramInt)
    {
      this.accountId = paramLong;
      this.name = paramString1;
      this.description = paramString2;
      this.quantity = paramInt;
    }
  }

  static class BidOrder
    implements Comparable<BidOrder>
  {
    long id;
    long height;
    Nxt.Account account;
    long asset;
    int quantity;
    long price;

    BidOrder(long paramLong1, Nxt.Account paramAccount, long paramLong2, int paramInt, long paramLong3)
    {
      this.id = paramLong1;
      this.height = Nxt.Block.getLastBlock().height;
      this.account = paramAccount;
      this.asset = paramLong2;
      this.quantity = paramInt;
      this.price = paramLong3;
    }

    public int compareTo(BidOrder paramBidOrder)
    {
      if (this.price > paramBidOrder.price)
        return -1;
      if (this.price < paramBidOrder.price)
        return 1;
      if (this.height < paramBidOrder.height)
        return -1;
      if (this.height > paramBidOrder.height)
        return 1;
      if (this.id < paramBidOrder.id)
        return -1;
      if (this.id > paramBidOrder.id)
        return 1;
      return 0;
    }
  }

  static class Block
    implements Serializable
  {
    static final long serialVersionUID = 0L;
    int version;
    int timestamp;
    long previousBlock;
    int numberOfTransactions;
    int totalAmount;
    int totalFee;
    int payloadLength;
    byte[] payloadHash;
    byte[] generatorPublicKey;
    byte[] generationSignature;
    byte[] blockSignature;
    int index;
    long[] transactions;
    long baseTarget;
    int height;
    long nextBlock;
    BigInteger cumulativeDifficulty;
    long prevBlockPtr;

    Block(int paramInt1, int paramInt2, long paramLong, int paramInt3, int paramInt4, int paramInt5, int paramInt6, byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, byte[] paramArrayOfByte4)
    {
      this.version = paramInt1;
      this.timestamp = paramInt2;
      this.previousBlock = paramLong;
      this.numberOfTransactions = paramInt3;
      this.totalAmount = paramInt4;
      this.totalFee = paramInt5;
      this.payloadLength = paramInt6;
      this.payloadHash = paramArrayOfByte1;
      this.generatorPublicKey = paramArrayOfByte2;
      this.generationSignature = paramArrayOfByte3;
      this.blockSignature = paramArrayOfByte4;
    }

    void analyze()
      throws Exception
    {
      if (this.previousBlock == 0L)
      {
        Nxt.lastBlock = 2680262203532249785L;
        Nxt.blocks.put(Long.valueOf(Nxt.lastBlock), this);
        this.baseTarget = 153722867L;
        this.cumulativeDifficulty = BigInteger.ZERO;
        Nxt.Account.addAccount(1739068987193023818L);
      }
      else
      {
        getLastBlock().nextBlock = getId();
        this.height = (getLastBlock().height + 1);
        Nxt.lastBlock = getId();
        Nxt.blocks.put(Long.valueOf(Nxt.lastBlock), this);
        this.baseTarget = getBaseTarget();
        this.cumulativeDifficulty = ((Block)Nxt.blocks.get(Long.valueOf(this.previousBlock))).cumulativeDifficulty.add(Nxt.two64.divide(BigInteger.valueOf(this.baseTarget)));
        Nxt.Account localAccount1 = (Nxt.Account)Nxt.accounts.get(Long.valueOf(Nxt.Account.getId(this.generatorPublicKey)));
        synchronized (localAccount1)
        {
          localAccount1.setBalance(localAccount1.balance + this.totalFee * 100L);
          localAccount1.setUnconfirmedBalance(localAccount1.unconfirmedBalance + this.totalFee * 100L);
        }
      }
      synchronized (Nxt.transactions)
      {
        for (int i = 0; i < this.numberOfTransactions; ++i)
        {
          Nxt.Transaction localTransaction = (Nxt.Transaction)Nxt.transactions.get(Long.valueOf(this.transactions[i]));
          long l1 = Nxt.Account.getId(localTransaction.senderPublicKey);
          Nxt.Account localAccount2 = (Nxt.Account)Nxt.accounts.get(Long.valueOf(l1));
          synchronized (localAccount2)
          {
            localAccount2.setBalance(localAccount2.balance - (localTransaction.amount + localTransaction.fee) * 100L);
            localAccount2.setUnconfirmedBalance(localAccount2.unconfirmedBalance - (localTransaction.amount + localTransaction.fee) * 100L);
            if (localAccount2.publicKey == null)
              localAccount2.publicKey = localTransaction.senderPublicKey;
          }
          ??? = (Nxt.Account)Nxt.accounts.get(Long.valueOf(localTransaction.recipient));
          if (??? == null)
            ??? = Nxt.Account.addAccount(localTransaction.recipient);
          Object localObject1;
          switch (localTransaction.type)
          {
          case 0:
            switch (localTransaction.subtype)
            {
            case 0:
              synchronized (???)
              {
                ((Nxt.Account)???).setBalance(((Nxt.Account)???).balance + localTransaction.amount * 100L);
                ((Nxt.Account)???).setUnconfirmedBalance(((Nxt.Account)???).unconfirmedBalance + localTransaction.amount * 100L);
              }
            }
            break;
          case 1:
            switch (localTransaction.subtype)
            {
            case 1:
              ??? = (Nxt.Transaction.MessagingAliasAssignmentAttachment)localTransaction.attachment;
              String str = ((Nxt.Transaction.MessagingAliasAssignmentAttachment)???).alias.toLowerCase();
              synchronized (Nxt.aliases)
              {
                localObject1 = (Nxt.Alias)Nxt.aliases.get(str);
                if (localObject1 == null)
                {
                  localObject1 = new Nxt.Alias(localAccount2, ((Nxt.Transaction.MessagingAliasAssignmentAttachment)???).alias, ((Nxt.Transaction.MessagingAliasAssignmentAttachment)???).uri, this.timestamp);
                  Nxt.aliases.put(str, localObject1);
                  Nxt.aliasIdToAliasMappings.put(Long.valueOf(localTransaction.getId()), localObject1);
                }
                else
                {
                  ((Nxt.Alias)localObject1).uri = ((Nxt.Transaction.MessagingAliasAssignmentAttachment)???).uri;
                  ((Nxt.Alias)localObject1).timestamp = this.timestamp;
                }
              }
            }
            break;
          case 2:
            switch (localTransaction.subtype)
            {
            case 0:
              ??? = (Nxt.Transaction.ColoredCoinsAssetIssuanceAttachment)localTransaction.attachment;
              long l2 = localTransaction.getId();
              localObject1 = new Nxt.Asset(l1, ((Nxt.Transaction.ColoredCoinsAssetIssuanceAttachment)???).name, ((Nxt.Transaction.ColoredCoinsAssetIssuanceAttachment)???).description, ((Nxt.Transaction.ColoredCoinsAssetIssuanceAttachment)???).quantity);
              synchronized (Nxt.assets)
              {
                Nxt.assets.put(Long.valueOf(l2), localObject1);
                Nxt.assetNameToIdMappings.put(((Nxt.Transaction.ColoredCoinsAssetIssuanceAttachment)???).name.toLowerCase(), Long.valueOf(l2));
              }
              synchronized (Nxt.askOrders)
              {
                Nxt.sortedAskOrders.put(Long.valueOf(l2), new TreeSet());
              }
              synchronized (Nxt.bidOrders)
              {
                Nxt.sortedBidOrders.put(Long.valueOf(l2), new TreeSet());
              }
              synchronized (localAccount2)
              {
                localAccount2.assetBalances.put(Long.valueOf(l2), Integer.valueOf(((Nxt.Transaction.ColoredCoinsAssetIssuanceAttachment)???).quantity));
                localAccount2.unconfirmedAssetBalances.put(Long.valueOf(l2), Integer.valueOf(((Nxt.Transaction.ColoredCoinsAssetIssuanceAttachment)???).quantity));
              }
            case 1:
              ??? = (Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localTransaction.attachment;
              synchronized (localAccount2)
              {
                localAccount2.assetBalances.put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).asset), Integer.valueOf(((Integer)localAccount2.assetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).asset))).intValue() - ((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).quantity));
                localAccount2.unconfirmedAssetBalances.put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).asset), Integer.valueOf(((Integer)localAccount2.unconfirmedAssetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).asset))).intValue() - ((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).quantity));
              }
              synchronized (???)
              {
                ??? = (Integer)((Nxt.Account)???).assetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).asset));
                if (??? == null)
                {
                  ((Nxt.Account)???).assetBalances.put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).asset), Integer.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).quantity));
                  ((Nxt.Account)???).unconfirmedAssetBalances.put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).asset), Integer.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).quantity));
                }
                else
                {
                  ((Nxt.Account)???).assetBalances.put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).asset), Integer.valueOf(???.intValue() + ((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).quantity));
                  ((Nxt.Account)???).unconfirmedAssetBalances.put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).asset), Integer.valueOf(((Integer)((Nxt.Account)???).unconfirmedAssetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).asset))).intValue() + ((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)???).quantity));
                }
              }
            case 2:
              ??? = (Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localTransaction.attachment;
              ??? = new Nxt.AskOrder(localTransaction.getId(), localAccount2, ((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).asset, ((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).quantity, ((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).price);
              synchronized (localAccount2)
              {
                localAccount2.assetBalances.put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).asset), Integer.valueOf(((Integer)localAccount2.assetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).asset))).intValue() - ((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).quantity));
                localAccount2.unconfirmedAssetBalances.put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).asset), Integer.valueOf(((Integer)localAccount2.unconfirmedAssetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).asset))).intValue() - ((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).quantity));
              }
              synchronized (Nxt.askOrders)
              {
                Nxt.askOrders.put(Long.valueOf(((Nxt.AskOrder)???).id), ???);
                ((TreeSet)Nxt.sortedAskOrders.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).asset))).add(???);
              }
              Nxt.matchOrders(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)???).asset);
              break;
            case 3:
              ??? = (Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)localTransaction.attachment;
              ??? = new Nxt.BidOrder(localTransaction.getId(), localAccount2, ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)???).asset, ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)???).quantity, ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)???).price);
              synchronized (localAccount2)
              {
                localAccount2.setBalance(localAccount2.balance - ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)???).quantity * ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)???).price);
                localAccount2.setUnconfirmedBalance(localAccount2.unconfirmedBalance - ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)???).quantity * ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)???).price);
              }
              synchronized (Nxt.bidOrders)
              {
                Nxt.bidOrders.put(Long.valueOf(((Nxt.BidOrder)???).id), ???);
                ((TreeSet)Nxt.sortedBidOrders.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)???).asset))).add(???);
              }
              Nxt.matchOrders(((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)???).asset);
              break;
            case 4:
              ??? = (Nxt.Transaction.ColoredCoinsAskOrderCancellationAttachment)localTransaction.attachment;
              synchronized (Nxt.askOrders)
              {
                ??? = (Nxt.AskOrder)Nxt.askOrders.remove(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderCancellationAttachment)???).order));
                ((TreeSet)Nxt.sortedAskOrders.get(Long.valueOf(((Nxt.AskOrder)???).asset))).remove(???);
              }
              synchronized (localAccount2)
              {
                localAccount2.assetBalances.put(Long.valueOf(((Nxt.AskOrder)???).asset), Integer.valueOf(((Integer)localAccount2.assetBalances.get(Long.valueOf(((Nxt.AskOrder)???).asset))).intValue() + ((Nxt.AskOrder)???).quantity));
                localAccount2.unconfirmedAssetBalances.put(Long.valueOf(((Nxt.AskOrder)???).asset), Integer.valueOf(((Integer)localAccount2.unconfirmedAssetBalances.get(Long.valueOf(((Nxt.AskOrder)???).asset))).intValue() + ((Nxt.AskOrder)???).quantity));
              }
            case 5:
              ??? = (Nxt.Transaction.ColoredCoinsBidOrderCancellationAttachment)localTransaction.attachment;
              synchronized (Nxt.bidOrders)
              {
                ??? = (Nxt.BidOrder)Nxt.bidOrders.remove(Long.valueOf(((Nxt.Transaction.ColoredCoinsBidOrderCancellationAttachment)???).order));
                ((TreeSet)Nxt.sortedBidOrders.get(Long.valueOf(((Nxt.BidOrder)???).asset))).remove(???);
              }
              synchronized (localAccount2)
              {
                localAccount2.setBalance(localAccount2.balance + ((Nxt.BidOrder)???).quantity * ((Nxt.BidOrder)???).price);
                localAccount2.setUnconfirmedBalance(localAccount2.unconfirmedBalance + ((Nxt.BidOrder)???).quantity * ((Nxt.BidOrder)???).price);
              }
            }
          }
        }
      }
    }

    static long getBaseTarget()
      throws Exception
    {
      if (Nxt.lastBlock == 2680262203532249785L)
        return ((Block)Nxt.blocks.get(Long.valueOf(2680262203532249785L))).baseTarget;
      Block localBlock1 = getLastBlock();
      Block localBlock2 = (Block)Nxt.blocks.get(Long.valueOf(localBlock1.previousBlock));
      long l1 = localBlock2.baseTarget;
      long l2 = BigInteger.valueOf(l1).multiply(BigInteger.valueOf(localBlock1.timestamp - localBlock2.timestamp)).divide(BigInteger.valueOf(60L)).longValue();
      if ((l2 < 0L) || (l2 > 153722867000000000L))
        l2 = 153722867000000000L;
      if (l2 < l1 / 2L)
        l2 = l1 / 2L;
      if (l2 == 0L)
        l2 = 1L;
      long l3 = l1 * 2L;
      if (l3 < 0L)
        l3 = 153722867000000000L;
      if (l2 > l3)
        l2 = l3;
      return l2;
    }

    static Block getBlock(JSONObject paramJSONObject)
    {
      int i = ((Long)paramJSONObject.get("version")).intValue();
      int j = ((Long)paramJSONObject.get("timestamp")).intValue();
      long l = new BigInteger((String)paramJSONObject.get("previousBlock")).longValue();
      int k = ((Long)paramJSONObject.get("numberOfTransactions")).intValue();
      int i1 = ((Long)paramJSONObject.get("totalAmount")).intValue();
      int i2 = ((Long)paramJSONObject.get("totalFee")).intValue();
      int i3 = ((Long)paramJSONObject.get("payloadLength")).intValue();
      byte[] arrayOfByte1 = Nxt.convert((String)paramJSONObject.get("payloadHash"));
      byte[] arrayOfByte2 = Nxt.convert((String)paramJSONObject.get("generatorPublicKey"));
      byte[] arrayOfByte3 = Nxt.convert((String)paramJSONObject.get("generationSignature"));
      byte[] arrayOfByte4 = Nxt.convert((String)paramJSONObject.get("blockSignature"));
      return new Block(i, j, l, k, i1, i2, i3, arrayOfByte1, arrayOfByte2, arrayOfByte3, arrayOfByte4);
    }

    byte[] getBytes()
    {
      ByteBuffer localByteBuffer = ByteBuffer.allocate(224);
      localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
      localByteBuffer.putInt(this.version);
      localByteBuffer.putInt(this.timestamp);
      localByteBuffer.putLong(this.previousBlock);
      localByteBuffer.putInt(this.numberOfTransactions);
      localByteBuffer.putInt(this.totalAmount);
      localByteBuffer.putInt(this.totalFee);
      localByteBuffer.putInt(this.payloadLength);
      localByteBuffer.put(this.payloadHash);
      localByteBuffer.put(this.generatorPublicKey);
      localByteBuffer.put(this.generationSignature);
      localByteBuffer.put(this.blockSignature);
      return localByteBuffer.array();
    }

    long getId()
      throws Exception
    {
      byte[] arrayOfByte = MessageDigest.getInstance("SHA-256").digest(getBytes());
      BigInteger localBigInteger = new BigInteger(1, new byte[] { arrayOfByte[7], arrayOfByte[6], arrayOfByte[5], arrayOfByte[4], arrayOfByte[3], arrayOfByte[2], arrayOfByte[1], arrayOfByte[0] });
      return localBigInteger.longValue();
    }

    JSONObject getJSONObject(HashMap<Long, Nxt.Transaction> paramHashMap)
    {
      JSONObject localJSONObject = new JSONObject();
      localJSONObject.put("version", Integer.valueOf(this.version));
      localJSONObject.put("timestamp", Integer.valueOf(this.timestamp));
      localJSONObject.put("previousBlock", Nxt.convert(this.previousBlock));
      localJSONObject.put("numberOfTransactions", Integer.valueOf(this.numberOfTransactions));
      localJSONObject.put("totalAmount", Integer.valueOf(this.totalAmount));
      localJSONObject.put("totalFee", Integer.valueOf(this.totalFee));
      localJSONObject.put("payloadLength", Integer.valueOf(this.payloadLength));
      localJSONObject.put("payloadHash", Nxt.convert(this.payloadHash));
      localJSONObject.put("generatorPublicKey", Nxt.convert(this.generatorPublicKey));
      localJSONObject.put("generationSignature", Nxt.convert(this.generationSignature));
      localJSONObject.put("blockSignature", Nxt.convert(this.blockSignature));
      JSONArray localJSONArray = new JSONArray();
      for (int i = 0; i < this.numberOfTransactions; ++i)
        localJSONArray.add(((Nxt.Transaction)paramHashMap.get(Long.valueOf(this.transactions[i]))).getJSONObject());
      localJSONObject.put("transactions", localJSONArray);
      return localJSONObject;
    }

    static Block getLastBlock()
    {
      return (Block)Nxt.blocks.get(Long.valueOf(Nxt.lastBlock));
    }

    static void loadBlocks(String paramString)
      throws Exception
    {
      FileInputStream localFileInputStream = new FileInputStream(paramString);
      ObjectInputStream localObjectInputStream = new ObjectInputStream(localFileInputStream);
      Nxt.blockCounter = localObjectInputStream.readInt();
      Nxt.blocks = (HashMap)localObjectInputStream.readObject();
      Nxt.lastBlock = localObjectInputStream.readLong();
      localObjectInputStream.close();
      localFileInputStream.close();
    }

    static boolean popLastBlock()
    {
      if (Nxt.lastBlock == 2680262203532249785L)
        return false;
      try
      {
        JSONObject localJSONObject1 = new JSONObject();
        localJSONObject1.put("response", "processNewData");
        JSONArray localJSONArray = new JSONArray();
        synchronized (Nxt.blocks)
        {
          localObject1 = getLastBlock();
          Nxt.Account localAccount1 = (Nxt.Account)Nxt.accounts.get(Long.valueOf(Nxt.Account.getId(((Block)localObject1).generatorPublicKey)));
          synchronized (localAccount1)
          {
            localAccount1.setBalance(localAccount1.balance - ((Block)localObject1).totalFee * 100L);
            localAccount1.setUnconfirmedBalance(localAccount1.unconfirmedBalance - ((Block)localObject1).totalFee * 100L);
          }
          synchronized (Nxt.transactions)
          {
            for (int i = 0; i < ((Block)localObject1).numberOfTransactions; ++i)
            {
              Nxt.Transaction localTransaction = (Nxt.Transaction)Nxt.transactions.remove(Long.valueOf(localObject1.transactions[i]));
              Nxt.unconfirmedTransactions.put(Long.valueOf(localObject1.transactions[i]), localTransaction);
              Nxt.Account localAccount2 = (Nxt.Account)Nxt.accounts.get(Long.valueOf(Nxt.Account.getId(localTransaction.senderPublicKey)));
              synchronized (localAccount2)
              {
                localAccount2.setBalance(localAccount2.balance + (localTransaction.amount + localTransaction.fee) * 100L);
              }
              ??? = (Nxt.Account)Nxt.accounts.get(Long.valueOf(localTransaction.recipient));
              synchronized (???)
              {
                ((Nxt.Account)???).setBalance(((Nxt.Account)???).balance - localTransaction.amount * 100L);
                ((Nxt.Account)???).setUnconfirmedBalance(((Nxt.Account)???).unconfirmedBalance - localTransaction.amount * 100L);
              }
              ??? = new JSONObject();
              ((JSONObject)???).put("index", Integer.valueOf(localTransaction.index));
              ((JSONObject)???).put("timestamp", Integer.valueOf(localTransaction.timestamp));
              ((JSONObject)???).put("deadline", Short.valueOf(localTransaction.deadline));
              ((JSONObject)???).put("recipient", Nxt.convert(localTransaction.recipient));
              ((JSONObject)???).put("amount", Integer.valueOf(localTransaction.amount));
              ((JSONObject)???).put("fee", Integer.valueOf(localTransaction.fee));
              ((JSONObject)???).put("sender", Nxt.convert(Nxt.Account.getId(localTransaction.senderPublicKey)));
              ((JSONObject)???).put("id", Nxt.convert(localTransaction.getId()));
              localJSONArray.add(???);
            }
          }
          ??? = new JSONArray();
          JSONObject localJSONObject2 = new JSONObject();
          localJSONObject2.put("index", Integer.valueOf(((Block)localObject1).index));
          localJSONObject2.put("timestamp", Integer.valueOf(((Block)localObject1).timestamp));
          localJSONObject2.put("numberOfTransactions", Integer.valueOf(((Block)localObject1).numberOfTransactions));
          localJSONObject2.put("totalAmount", Integer.valueOf(((Block)localObject1).totalAmount));
          localJSONObject2.put("totalFee", Integer.valueOf(((Block)localObject1).totalFee));
          localJSONObject2.put("payloadLength", Integer.valueOf(((Block)localObject1).payloadLength));
          localJSONObject2.put("generator", Nxt.convert(Nxt.Account.getId(((Block)localObject1).generatorPublicKey)));
          localJSONObject2.put("height", Integer.valueOf(((Block)localObject1).height));
          localJSONObject2.put("version", Integer.valueOf(((Block)localObject1).version));
          localJSONObject2.put("block", Nxt.convert(((Block)localObject1).getId()));
          localJSONObject2.put("baseTarget", BigInteger.valueOf(((Block)localObject1).baseTarget).multiply(BigInteger.valueOf(100000L)).divide(BigInteger.valueOf(153722867L)));
          ((JSONArray)???).add(localJSONObject2);
          localJSONObject1.put("addedOrphanedBlocks", ???);
          Nxt.lastBlock = ((Block)localObject1).previousBlock;
        }
        if (localJSONArray.size() > 0)
          localJSONObject1.put("addedUnconfirmedTransactions", localJSONArray);
        Object localObject1 = Nxt.users.values().iterator();
        while (((Iterator)localObject1).hasNext())
        {
          ??? = (Nxt.User)((Iterator)localObject1).next();
          ((Nxt.User)???).send(localJSONObject1);
        }
      }
      catch (Exception localException)
      {
        Nxt.logMessage("19: " + localException.toString());
        return false;
      }
      return true;
    }

    static boolean pushBlock(ByteBuffer paramByteBuffer, boolean paramBoolean)
    {
      paramByteBuffer.flip();
      int i = paramByteBuffer.getInt();
      if (i != 1)
        return false;
      int j = paramByteBuffer.getInt();
      long l1 = paramByteBuffer.getLong();
      int k = paramByteBuffer.getInt();
      int l = paramByteBuffer.getInt();
      int i1 = paramByteBuffer.getInt();
      int i2 = paramByteBuffer.getInt();
      byte[] arrayOfByte1 = new byte[32];
      paramByteBuffer.get(arrayOfByte1);
      byte[] arrayOfByte2 = new byte[32];
      paramByteBuffer.get(arrayOfByte2);
      byte[] arrayOfByte3 = new byte[64];
      paramByteBuffer.get(arrayOfByte3);
      byte[] arrayOfByte4 = new byte[64];
      paramByteBuffer.get(arrayOfByte4);
      if (getLastBlock().previousBlock == l1)
        return false;
      int i3 = Nxt.getEpochTime(System.currentTimeMillis());
      if ((j > i3 + 15) || (j <= getLastBlock().timestamp))
        return false;
      if ((i2 > 32640) || (224 + i2 != paramByteBuffer.capacity()))
        return false;
      Block localBlock = new Block(i, j, l1, k, l, i1, i2, arrayOfByte1, arrayOfByte2, arrayOfByte3, arrayOfByte4);
      synchronized (Nxt.blocks)
      {
        localBlock.index = (++Nxt.blockCounter);
      }
      try
      {
        if ((localBlock.previousBlock != Nxt.lastBlock) || (Nxt.blocks.get(Long.valueOf(localBlock.getId())) != null) || (!localBlock.verifyGenerationSignature()) || (!localBlock.verifyBlockSignature()))
          return false;
        ??? = new HashMap();
        HashSet localHashSet = new HashSet();
        localBlock.transactions = new long[localBlock.numberOfTransactions];
        for (int i4 = 0; i4 < localBlock.numberOfTransactions; ++i4)
        {
          localObject1 = Nxt.Transaction.getTransaction(paramByteBuffer);
          synchronized (Nxt.transactions)
          {
            ((Nxt.Transaction)localObject1).index = (++Nxt.transactionCounter);
          }
          if (((HashMap)???).put(Long.valueOf(localBlock.transactions[i4] = ((Nxt.Transaction)localObject1).getId()), localObject1) != null)
            return false;
          switch (((Nxt.Transaction)localObject1).type)
          {
          case 1:
            switch (((Nxt.Transaction)localObject1).subtype)
            {
            case 1:
              if (!localHashSet.add(((Nxt.Transaction.MessagingAliasAssignmentAttachment)((Nxt.Transaction)localObject1).attachment).alias.toLowerCase()))
                return false;
            }
          }
        }
        Arrays.sort(localBlock.transactions);
        HashMap localHashMap = new HashMap();
        Object localObject1 = new HashMap();
        int i5 = 0;
        int i6 = 0;
        Object localObject3;
        Object localObject4;
        Object localObject5;
        Object localObject6;
        for (int i7 = 0; i7 < localBlock.numberOfTransactions; ++i7)
        {
          localObject2 = (Nxt.Transaction)((HashMap)???).get(Long.valueOf(localBlock.transactions[i7]));
          if ((((Nxt.Transaction)localObject2).timestamp > i3 + 15) || (((Nxt.Transaction)localObject2).deadline < 1) || ((((Nxt.Transaction)localObject2).timestamp + ((Nxt.Transaction)localObject2).deadline * 60 < j) && (getLastBlock().height > 303)) || (((Nxt.Transaction)localObject2).fee <= 0) || (!((Nxt.Transaction)localObject2).validateAttachment()) || (Nxt.transactions.get(Long.valueOf(localBlock.transactions[i7])) != null) || ((((Nxt.Transaction)localObject2).referencedTransaction != 0L) && (Nxt.transactions.get(Long.valueOf(((Nxt.Transaction)localObject2).referencedTransaction)) == null) && (((HashMap)???).get(Long.valueOf(((Nxt.Transaction)localObject2).referencedTransaction)) == null)))
            break;
          if ((Nxt.unconfirmedTransactions.get(Long.valueOf(localBlock.transactions[i7])) == null) && (!((Nxt.Transaction)localObject2).verify()))
            break;
          long l2 = Nxt.Account.getId(((Nxt.Transaction)localObject2).senderPublicKey);
          localObject3 = (Long)localHashMap.get(Long.valueOf(l2));
          if (localObject3 == null)
            localObject3 = new Long(0L);
          localHashMap.put(Long.valueOf(l2), Long.valueOf(((Long)localObject3).longValue() + (((Nxt.Transaction)localObject2).amount + ((Nxt.Transaction)localObject2).fee) * 100L));
          if (((Nxt.Transaction)localObject2).type == 0)
          {
            if (((Nxt.Transaction)localObject2).subtype != 0)
              break;
            i5 += ((Nxt.Transaction)localObject2).amount;
          }
          else
          {
            if (((Nxt.Transaction)localObject2).type == 1)
            {
              if (((Nxt.Transaction)localObject2).subtype == 1)
                break label1156;
              break;
            }
            if (((Nxt.Transaction)localObject2).type != 2)
              break;
            if (((Nxt.Transaction)localObject2).subtype == 1)
            {
              localObject4 = (Nxt.Transaction.ColoredCoinsAssetTransferAttachment)((Nxt.Transaction)localObject2).attachment;
              localObject5 = (HashMap)((HashMap)localObject1).get(Long.valueOf(l2));
              if (localObject5 == null)
              {
                localObject5 = new HashMap();
                ((HashMap)localObject1).put(Long.valueOf(l2), localObject5);
              }
              localObject6 = (Long)((HashMap)localObject5).get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localObject4).asset));
              if (localObject6 == null)
                localObject6 = new Long(0L);
              ((HashMap)localObject5).put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localObject4).asset), Long.valueOf(((Long)localObject6).longValue() + ((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localObject4).quantity));
            }
            else if (((Nxt.Transaction)localObject2).subtype == 2)
            {
              localObject4 = (Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)((Nxt.Transaction)localObject2).attachment;
              localObject5 = (HashMap)((HashMap)localObject1).get(Long.valueOf(l2));
              if (localObject5 == null)
              {
                localObject5 = new HashMap();
                ((HashMap)localObject1).put(Long.valueOf(l2), localObject5);
              }
              localObject6 = (Long)((HashMap)localObject5).get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localObject4).asset));
              if (localObject6 == null)
                localObject6 = new Long(0L);
              ((HashMap)localObject5).put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localObject4).asset), Long.valueOf(((Long)localObject6).longValue() + ((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localObject4).quantity));
            }
            else if (((Nxt.Transaction)localObject2).subtype == 3)
            {
              localObject4 = (Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)((Nxt.Transaction)localObject2).attachment;
              localHashMap.put(Long.valueOf(l2), Long.valueOf(((Long)localObject3).longValue() + ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)localObject4).quantity * ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)localObject4).price));
            }
            else
            {
              if ((((Nxt.Transaction)localObject2).subtype != 0) && (((Nxt.Transaction)localObject2).subtype != 4) && (((Nxt.Transaction)localObject2).subtype != 5))
                break;
            }
          }
          label1156: i6 += ((Nxt.Transaction)localObject2).fee;
        }
        if ((i7 != localBlock.numberOfTransactions) || (i5 != localBlock.totalAmount) || (i6 != localBlock.totalFee))
          return false;
        Object localObject2 = MessageDigest.getInstance("SHA-256");
        for (i7 = 0; i7 < localBlock.numberOfTransactions; ++i7)
          ((MessageDigest)localObject2).update(((Nxt.Transaction)((HashMap)???).get(Long.valueOf(localBlock.transactions[i7]))).getBytes());
        if (!Arrays.equals(((MessageDigest)localObject2).digest(), localBlock.payloadHash))
          return false;
        synchronized (Nxt.blocks)
        {
          localObject3 = localHashMap.entrySet().iterator();
          Map.Entry localEntry;
          while (((Iterator)localObject3).hasNext())
          {
            localEntry = (Map.Entry)((Iterator)localObject3).next();
            localObject4 = (Nxt.Account)Nxt.accounts.get(localEntry.getKey());
            if (((Nxt.Account)localObject4).balance < ((Long)localEntry.getValue()).longValue())
              return false;
          }
          localObject3 = ((HashMap)localObject1).entrySet().iterator();
          while (((Iterator)localObject3).hasNext())
          {
            localEntry = (Map.Entry)((Iterator)localObject3).next();
            localObject4 = (Nxt.Account)Nxt.accounts.get(localEntry.getKey());
            localObject6 = ((HashMap)localEntry.getValue()).entrySet().iterator();
            while (((Iterator)localObject6).hasNext())
            {
              localObject5 = (Map.Entry)((Iterator)localObject6).next();
              long l4 = ((Long)((Map.Entry)localObject5).getKey()).longValue();
              long l5 = ((Long)((Map.Entry)localObject5).getValue()).longValue();
              if (((Integer)((Nxt.Account)localObject4).assetBalances.get(Long.valueOf(l4))).intValue() < l5)
                return false;
            }
          }
          if (localBlock.previousBlock != Nxt.lastBlock)
            return false;
          synchronized (Nxt.transactions)
          {
            localObject4 = ((HashMap)???).entrySet().iterator();
            while (((Iterator)localObject4).hasNext())
            {
              localObject3 = (Map.Entry)((Iterator)localObject4).next();
              localObject5 = (Nxt.Transaction)((Map.Entry)localObject3).getValue();
              ((Nxt.Transaction)localObject5).height = localBlock.height;
              Nxt.transactions.put((Long)((Map.Entry)localObject3).getKey(), localObject5);
            }
          }
          localBlock.analyze();
          ??? = new JSONArray();
          localObject3 = new JSONArray();
          localObject5 = ((HashMap)???).entrySet().iterator();
          Object localObject8;
          while (((Iterator)localObject5).hasNext())
          {
            localObject4 = (Map.Entry)((Iterator)localObject5).next();
            localObject6 = (Nxt.Transaction)((Map.Entry)localObject4).getValue();
            localJSONObject = new JSONObject();
            localJSONObject.put("index", Integer.valueOf(((Nxt.Transaction)localObject6).index));
            localJSONObject.put("blockTimestamp", Integer.valueOf(localBlock.timestamp));
            localJSONObject.put("transactionTimestamp", Integer.valueOf(((Nxt.Transaction)localObject6).timestamp));
            localJSONObject.put("sender", Nxt.convert(Nxt.Account.getId(((Nxt.Transaction)localObject6).senderPublicKey)));
            localJSONObject.put("recipient", Nxt.convert(((Nxt.Transaction)localObject6).recipient));
            localJSONObject.put("amount", Integer.valueOf(((Nxt.Transaction)localObject6).amount));
            localJSONObject.put("fee", Integer.valueOf(((Nxt.Transaction)localObject6).fee));
            localJSONObject.put("id", Nxt.convert(((Nxt.Transaction)localObject6).getId()));
            ((JSONArray)???).add(localJSONObject);
            localObject7 = (Nxt.Transaction)Nxt.unconfirmedTransactions.remove(((Map.Entry)localObject4).getKey());
            if (localObject7 == null)
              continue;
            localObject8 = new JSONObject();
            ((JSONObject)localObject8).put("index", Integer.valueOf(((Nxt.Transaction)localObject7).index));
            ((JSONArray)localObject3).add(localObject8);
            localObject9 = (Nxt.Account)Nxt.accounts.get(Long.valueOf(Nxt.Account.getId(((Nxt.Transaction)localObject7).senderPublicKey)));
            synchronized (localObject9)
            {
              ((Nxt.Account)localObject9).setUnconfirmedBalance(((Nxt.Account)localObject9).unconfirmedBalance + (((Nxt.Transaction)localObject7).amount + ((Nxt.Transaction)localObject7).fee) * 100L);
            }
          }
          long l3 = localBlock.getId();
          for (i7 = 0; i7 < localBlock.transactions.length; ++i7)
            ((Nxt.Transaction)Nxt.transactions.get(Long.valueOf(localBlock.transactions[i7]))).block = l3;
          if (paramBoolean)
          {
            Nxt.Transaction.saveTransactions("transactions.nxt");
            saveBlocks("blocks.nxt", false);
          }
          if (localBlock.timestamp >= i3 - 15)
          {
            localObject6 = localBlock.getJSONObject(Nxt.transactions);
            ((JSONObject)localObject6).put("requestType", "processBlock");
            Nxt.Peer.sendToAllPeers((JSONObject)localObject6);
          }
          localObject6 = new JSONArray();
          JSONObject localJSONObject = new JSONObject();
          localJSONObject.put("index", Integer.valueOf(localBlock.index));
          localJSONObject.put("timestamp", Integer.valueOf(localBlock.timestamp));
          localJSONObject.put("numberOfTransactions", Integer.valueOf(localBlock.numberOfTransactions));
          localJSONObject.put("totalAmount", Integer.valueOf(localBlock.totalAmount));
          localJSONObject.put("totalFee", Integer.valueOf(localBlock.totalFee));
          localJSONObject.put("payloadLength", Integer.valueOf(localBlock.payloadLength));
          localJSONObject.put("generator", Nxt.convert(Nxt.Account.getId(localBlock.generatorPublicKey)));
          localJSONObject.put("height", Integer.valueOf(getLastBlock().height));
          localJSONObject.put("version", Integer.valueOf(localBlock.version));
          localJSONObject.put("block", Nxt.convert(localBlock.getId()));
          localJSONObject.put("baseTarget", BigInteger.valueOf(localBlock.baseTarget).multiply(BigInteger.valueOf(100000L)).divide(BigInteger.valueOf(153722867L)));
          ((JSONArray)localObject6).add(localJSONObject);
          Object localObject7 = new JSONObject();
          ((JSONObject)localObject7).put("response", "processNewData");
          ((JSONObject)localObject7).put("addedConfirmedTransactions", ???);
          if (((JSONArray)localObject3).size() > 0)
            ((JSONObject)localObject7).put("removedUnconfirmedTransactions", localObject3);
          ((JSONObject)localObject7).put("addedRecentBlocks", localObject6);
          Object localObject9 = Nxt.users.values().iterator();
          while (((Iterator)localObject9).hasNext())
          {
            localObject8 = (Nxt.User)((Iterator)localObject9).next();
            ((Nxt.User)localObject8).send((JSONObject)localObject7);
          }
        }
        return true;
      }
      catch (Exception localException)
      {
        Nxt.logMessage("11: " + localException.toString());
      }
      return false;
    }

    static void saveBlocks(String paramString, boolean paramBoolean)
      throws Exception
    {
      synchronized (Nxt.blocks)
      {
        FileOutputStream localFileOutputStream = new FileOutputStream(paramString);
        ObjectOutputStream localObjectOutputStream = new ObjectOutputStream(localFileOutputStream);
        localObjectOutputStream.writeInt(Nxt.blockCounter);
        localObjectOutputStream.writeObject(Nxt.blocks);
        localObjectOutputStream.writeLong(Nxt.lastBlock);
        localObjectOutputStream.close();
        localFileOutputStream.close();
        if (paramBoolean)
        {
          ByteBuffer localByteBuffer = ByteBuffer.allocate(32864);
          localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
          long l1 = 2680262203532249785L;
          long l2 = -1L;
          long l3 = 0L;
          MessageDigest localMessageDigest = MessageDigest.getInstance("SHA-256");
          do
          {
            Block localBlock = (Block)Nxt.blocks.get(Long.valueOf(l1));
            localByteBuffer.clear();
            localByteBuffer.putLong(l2);
            localByteBuffer.put(localBlock.getBytes());
            for (int i = 0; i < localBlock.numberOfTransactions; ++i)
              localByteBuffer.put(((Nxt.Transaction)Nxt.transactions.get(Long.valueOf(localBlock.transactions[i]))).getBytes());
            localByteBuffer.flip();
            byte[] arrayOfByte = new byte[localByteBuffer.limit()];
            localByteBuffer.get(arrayOfByte);
            MappedByteBuffer localMappedByteBuffer = Nxt.blockchainChannel.map(FileChannel.MapMode.READ_WRITE, l3, 32 + arrayOfByte.length);
            localMappedByteBuffer.put(localMessageDigest.digest(arrayOfByte));
            localMappedByteBuffer.put(arrayOfByte);
            l2 = l3;
            l3 += 32 + arrayOfByte.length;
            l1 = localBlock.nextBlock;
          }
          while (l1 != 0L);
        }
      }
    }

    boolean verifyBlockSignature()
      throws Exception
    {
      Nxt.Account localAccount = (Nxt.Account)Nxt.accounts.get(Long.valueOf(Nxt.Account.getId(this.generatorPublicKey)));
      if (localAccount == null)
        return false;
      if (localAccount.publicKey == null)
        localAccount.publicKey = this.generatorPublicKey;
      else if (!Arrays.equals(this.generatorPublicKey, localAccount.publicKey))
        return false;
      byte[] arrayOfByte1 = getBytes();
      byte[] arrayOfByte2 = new byte[arrayOfByte1.length - 64];
      System.arraycopy(arrayOfByte1, 0, arrayOfByte2, 0, arrayOfByte2.length);
      return Nxt.Crypto.verify(this.blockSignature, arrayOfByte2, this.generatorPublicKey);
    }

    boolean verifyGenerationSignature()
    {
      try
      {
        Block localBlock;
        Nxt.Account localAccount;
        BigInteger localBigInteger1;
        byte[] arrayOfByte;
        BigInteger localBigInteger2;
        if (getLastBlock().height <= 20000)
        {
          localBlock = (Block)Nxt.blocks.get(Long.valueOf(this.previousBlock));
          if (localBlock == null)
            return false;
          if (!Nxt.Crypto.verify(this.generationSignature, localBlock.generationSignature, this.generatorPublicKey))
            return false;
          localAccount = (Nxt.Account)Nxt.accounts.get(Long.valueOf(Nxt.Account.getId(this.generatorPublicKey)));
          if ((localAccount == null) || (localAccount.getEffectiveBalance() == 0))
            return false;
          int i = this.timestamp - localBlock.timestamp;
          localBigInteger1 = BigInteger.valueOf(getBaseTarget()).multiply(BigInteger.valueOf(localAccount.getEffectiveBalance())).multiply(BigInteger.valueOf(i));
          arrayOfByte = MessageDigest.getInstance("SHA-256").digest(this.generationSignature);
          localBigInteger2 = new BigInteger(1, new byte[] { arrayOfByte[7], arrayOfByte[6], arrayOfByte[5], arrayOfByte[4], arrayOfByte[3], arrayOfByte[2], arrayOfByte[1], arrayOfByte[0] });
          if (localBigInteger2.compareTo(localBigInteger1) >= 0)
            return false;
        }
        else
        {
          localBlock = (Block)Nxt.blocks.get(Long.valueOf(this.previousBlock));
          if (localBlock == null)
            return false;
          if (!Nxt.Crypto.verify(this.generationSignature, localBlock.generationSignature, this.generatorPublicKey))
            return false;
          localAccount = (Nxt.Account)Nxt.accounts.get(Long.valueOf(Nxt.Account.getId(this.generatorPublicKey)));
          if ((localAccount == null) || (localAccount.getEffectiveBalance() == 0))
            return false;
          int j = this.timestamp - localBlock.timestamp;
          localBigInteger1 = BigInteger.valueOf(getBaseTarget()).multiply(BigInteger.valueOf(localAccount.getEffectiveBalance())).multiply(BigInteger.valueOf(j));
          arrayOfByte = MessageDigest.getInstance("SHA-256").digest(this.generationSignature);
          localBigInteger2 = new BigInteger(1, new byte[] { arrayOfByte[7], arrayOfByte[6], arrayOfByte[5], arrayOfByte[4], arrayOfByte[3], arrayOfByte[2], arrayOfByte[1], arrayOfByte[0] });
          if (localBigInteger2.compareTo(localBigInteger1) >= 0)
            return false;
        }
        return true;
      }
      catch (Exception localException)
      {
      }
      return false;
    }
  }

  static class Crypto
  {
    static byte[] getPublicKey(String paramString)
    {
      try
      {
        byte[] arrayOfByte = new byte[32];
        Nxt.Curve25519.keygen(arrayOfByte, null, MessageDigest.getInstance("SHA-256").digest(paramString.getBytes("UTF-8")));
        return arrayOfByte;
      }
      catch (Exception localException)
      {
      }
      return null;
    }

    static byte[] sign(byte[] paramArrayOfByte, String paramString)
    {
      try
      {
        byte[] arrayOfByte1 = new byte[32];
        byte[] arrayOfByte2 = new byte[32];
        MessageDigest localMessageDigest = MessageDigest.getInstance("SHA-256");
        Nxt.Curve25519.keygen(arrayOfByte1, arrayOfByte2, localMessageDigest.digest(paramString.getBytes("UTF-8")));
        byte[] arrayOfByte3 = localMessageDigest.digest(paramArrayOfByte);
        localMessageDigest.update(arrayOfByte3);
        byte[] arrayOfByte4 = localMessageDigest.digest(arrayOfByte2);
        byte[] arrayOfByte5 = new byte[32];
        Nxt.Curve25519.keygen(arrayOfByte5, null, arrayOfByte4);
        localMessageDigest.update(arrayOfByte3);
        byte[] arrayOfByte6 = localMessageDigest.digest(arrayOfByte5);
        byte[] arrayOfByte7 = new byte[32];
        Nxt.Curve25519.sign(arrayOfByte7, arrayOfByte6, arrayOfByte4, arrayOfByte2);
        byte[] arrayOfByte8 = new byte[64];
        System.arraycopy(arrayOfByte7, 0, arrayOfByte8, 0, 32);
        System.arraycopy(arrayOfByte6, 0, arrayOfByte8, 32, 32);
        return arrayOfByte8;
      }
      catch (Exception localException)
      {
      }
      return null;
    }

    static boolean verify(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3)
    {
      try
      {
        byte[] arrayOfByte1 = new byte[32];
        byte[] arrayOfByte2 = new byte[32];
        System.arraycopy(paramArrayOfByte1, 0, arrayOfByte2, 0, 32);
        byte[] arrayOfByte3 = new byte[32];
        System.arraycopy(paramArrayOfByte1, 32, arrayOfByte3, 0, 32);
        Nxt.Curve25519.verify(arrayOfByte1, arrayOfByte2, arrayOfByte3, paramArrayOfByte3);
        MessageDigest localMessageDigest = MessageDigest.getInstance("SHA-256");
        byte[] arrayOfByte4 = localMessageDigest.digest(paramArrayOfByte2);
        localMessageDigest.update(arrayOfByte4);
        byte[] arrayOfByte5 = localMessageDigest.digest(arrayOfByte1);
        return Arrays.equals(arrayOfByte3, arrayOfByte5);
      }
      catch (Exception localException)
      {
      }
      return false;
    }
  }

  static class Curve25519
  {
    public static final int KEY_SIZE = 32;
    public static final byte[] ZERO = new byte[32];
    public static final byte[] PRIME = { -19, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 127 };
    public static final byte[] ORDER = { -19, -45, -11, 92, 26, 99, 18, 88, -42, -100, -9, -94, -34, -7, -34, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16 };
    private static final int P25 = 33554431;
    private static final int P26 = 67108863;
    private static final byte[] ORDER_TIMES_8 = { 104, -97, -82, -25, -46, 24, -109, -64, -78, -26, -68, 23, -11, -50, -9, -90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -128 };
    private static final Nxt.Curve25519.long10 BASE_2Y = new Nxt.Curve25519.long10(39999547L, 18689728L, 59995525L, 1648697L, 57546132L, 24010086L, 19059592L, 5425144L, 63499247L, 16420658L);
    private static final Nxt.Curve25519.long10 BASE_R2Y = new Nxt.Curve25519.long10(5744L, 8160848L, 4790893L, 13779497L, 35730846L, 12541209L, 49101323L, 30047407L, 40071253L, 6226132L);

    public static final void clamp(byte[] paramArrayOfByte)
    {
      paramArrayOfByte[31] = (byte)(paramArrayOfByte[31] & 0x7F);
      paramArrayOfByte[31] = (byte)(paramArrayOfByte[31] | 0x40);
      int tmp22_21 = 0;
      paramArrayOfByte[tmp22_21] = (byte)(paramArrayOfByte[tmp22_21] & 0xF8);
    }

    public static final void keygen(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3)
    {
      clamp(paramArrayOfByte3);
      core(paramArrayOfByte1, paramArrayOfByte2, paramArrayOfByte3, null);
    }

    public static final void curve(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3)
    {
      core(paramArrayOfByte1, null, paramArrayOfByte2, paramArrayOfByte3);
    }

    public static final boolean sign(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, byte[] paramArrayOfByte4)
    {
      byte[] arrayOfByte1 = new byte[65];
      byte[] arrayOfByte2 = new byte[33];
      for (int j = 0; j < 32; ++j)
        paramArrayOfByte1[j] = 0;
      j = mula_small(paramArrayOfByte1, paramArrayOfByte3, 0, paramArrayOfByte2, 32, -1);
      mula_small(paramArrayOfByte1, paramArrayOfByte1, 0, ORDER, 32, (15 - paramArrayOfByte1[31]) / 16);
      mula32(arrayOfByte1, paramArrayOfByte1, paramArrayOfByte4, 32, 1);
      divmod(arrayOfByte2, arrayOfByte1, 64, ORDER, 32);
      int i = 0;
      for (j = 0; j < 32; ++j)
        i |= (paramArrayOfByte1[j] = arrayOfByte1[j]);
      return i != 0;
    }

    public static final void verify(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, byte[] paramArrayOfByte4)
    {
      byte[] arrayOfByte = new byte[32];
      Nxt.Curve25519.long10[] arrayOflong101 = { new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10() };
      Nxt.Curve25519.long10[] arrayOflong102 = { new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10() };
      Nxt.Curve25519.long10[] arrayOflong103 = { new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10() };
      Nxt.Curve25519.long10[] arrayOflong104 = { new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10() };
      Nxt.Curve25519.long10[] arrayOflong105 = { new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10() };
      Nxt.Curve25519.long10[] arrayOflong106 = { new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10() };
      int i = 0;
      int j = 0;
      int k = 0;
      int l = 0;
      set(arrayOflong101[0], 9);
      unpack(arrayOflong101[1], paramArrayOfByte4);
      x_to_y2(arrayOflong105[0], arrayOflong106[0], arrayOflong101[1]);
      sqrt(arrayOflong105[0], arrayOflong106[0]);
      int i2 = is_negative(arrayOflong105[0]);
      arrayOflong106[0]._0 += 39420360L;
      mul(arrayOflong106[1], BASE_2Y, arrayOflong105[0]);
      sub(arrayOflong105[i2], arrayOflong106[0], arrayOflong106[1]);
      add(arrayOflong105[(1 - i2)], arrayOflong106[0], arrayOflong106[1]);
      cpy(arrayOflong106[0], arrayOflong101[1]);
      arrayOflong106[0]._0 -= 9L;
      sqr(arrayOflong106[1], arrayOflong106[0]);
      recip(arrayOflong106[0], arrayOflong106[1], 0);
      mul(arrayOflong102[0], arrayOflong105[0], arrayOflong106[0]);
      sub(arrayOflong102[0], arrayOflong102[0], arrayOflong101[1]);
      arrayOflong102[0]._0 -= 486671L;
      mul(arrayOflong102[1], arrayOflong105[1], arrayOflong106[0]);
      sub(arrayOflong102[1], arrayOflong102[1], arrayOflong101[1]);
      arrayOflong102[1]._0 -= 486671L;
      mul_small(arrayOflong102[0], arrayOflong102[0], 1L);
      mul_small(arrayOflong102[1], arrayOflong102[1], 1L);
      for (int i1 = 0; i1 < 32; ++i1)
      {
        i = i >> 8 ^ paramArrayOfByte2[i1] & 0xFF ^ (paramArrayOfByte2[i1] & 0xFF) << 1;
        j = j >> 8 ^ paramArrayOfByte3[i1] & 0xFF ^ (paramArrayOfByte3[i1] & 0xFF) << 1;
        l = i ^ j ^ 0xFFFFFFFF;
        k = l & (k & 0x80) >> 7 ^ i;
        k ^= l & (k & 0x1) << 1;
        k ^= l & (k & 0x2) << 1;
        k ^= l & (k & 0x4) << 1;
        k ^= l & (k & 0x8) << 1;
        k ^= l & (k & 0x10) << 1;
        k ^= l & (k & 0x20) << 1;
        k ^= l & (k & 0x40) << 1;
        arrayOfByte[i1] = (byte)k;
      }
      k = (l & (k & 0x80) << 1 ^ i) >> 8;
      set(arrayOflong103[0], 1);
      cpy(arrayOflong103[1], arrayOflong101[k]);
      cpy(arrayOflong103[2], arrayOflong102[0]);
      set(arrayOflong104[0], 0);
      set(arrayOflong104[1], 1);
      set(arrayOflong104[2], 1);
      i = 0;
      j = 0;
      i1 = 32;
      while (i1-- != 0)
      {
        i = i << 8 | paramArrayOfByte2[i1] & 0xFF;
        j = j << 8 | paramArrayOfByte3[i1] & 0xFF;
        k = k << 8 | arrayOfByte[i1] & 0xFF;
        i2 = 8;
        while (i2-- != 0)
        {
          mont_prep(arrayOflong105[0], arrayOflong106[0], arrayOflong103[0], arrayOflong104[0]);
          mont_prep(arrayOflong105[1], arrayOflong106[1], arrayOflong103[1], arrayOflong104[1]);
          mont_prep(arrayOflong105[2], arrayOflong106[2], arrayOflong103[2], arrayOflong104[2]);
          i3 = ((i ^ i >> 1) >> i2 & 0x1) + ((j ^ j >> 1) >> i2 & 0x1);
          mont_dbl(arrayOflong103[2], arrayOflong104[2], arrayOflong105[i3], arrayOflong106[i3], arrayOflong103[0], arrayOflong104[0]);
          i3 = k >> i2 & 0x2 ^ (k >> i2 & 0x1) << 1;
          mont_add(arrayOflong105[1], arrayOflong106[1], arrayOflong105[i3], arrayOflong106[i3], arrayOflong103[1], arrayOflong104[1], arrayOflong101[(k >> i2 & 0x1)]);
          mont_add(arrayOflong105[2], arrayOflong106[2], arrayOflong105[0], arrayOflong106[0], arrayOflong103[2], arrayOflong104[2], arrayOflong102[(((i ^ j) >> i2 & 0x2) >> 1)]);
        }
      }
      int i3 = (i & 0x1) + (j & 0x1);
      recip(arrayOflong105[0], arrayOflong104[i3], 0);
      mul(arrayOflong105[1], arrayOflong103[i3], arrayOflong105[0]);
      pack(arrayOflong105[1], paramArrayOfByte1);
    }

    private static final void cpy32(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2)
    {
      for (int i = 0; i < 32; ++i)
        paramArrayOfByte1[i] = paramArrayOfByte2[i];
    }

    private static final int mula_small(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, int paramInt1, byte[] paramArrayOfByte3, int paramInt2, int paramInt3)
    {
      int i = 0;
      for (int j = 0; j < paramInt2; ++j)
      {
        i += (paramArrayOfByte2[(j + paramInt1)] & 0xFF) + paramInt3 * (paramArrayOfByte3[j] & 0xFF);
        paramArrayOfByte1[(j + paramInt1)] = (byte)i;
        i >>= 8;
      }
      return i;
    }

    private static final int mula32(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, int paramInt1, int paramInt2)
    {
      int i = 0;
      for (int j = 0; j < paramInt1; ++j)
      {
        int k = paramInt2 * (paramArrayOfByte3[j] & 0xFF);
        i += mula_small(paramArrayOfByte1, paramArrayOfByte1, j, paramArrayOfByte2, 31, k) + (paramArrayOfByte1[(j + 31)] & 0xFF) + k * (paramArrayOfByte2[31] & 0xFF);
        paramArrayOfByte1[(j + 31)] = (byte)i;
        i >>= 8;
      }
      paramArrayOfByte1[(j + 31)] = (byte)(i + (paramArrayOfByte1[(j + 31)] & 0xFF));
      return i >> 8;
    }

    private static final void divmod(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, int paramInt1, byte[] paramArrayOfByte3, int paramInt2)
    {
      int i = 0;
      int j = (paramArrayOfByte3[(paramInt2 - 1)] & 0xFF) << 8;
      if (paramInt2 > 1)
        j |= paramArrayOfByte3[(paramInt2 - 2)] & 0xFF;
      while (paramInt1-- >= paramInt2)
      {
        int k = i << 16 | (paramArrayOfByte2[paramInt1] & 0xFF) << 8;
        if (paramInt1 > 0)
          k |= paramArrayOfByte2[(paramInt1 - 1)] & 0xFF;
        k /= j;
        i += mula_small(paramArrayOfByte2, paramArrayOfByte2, paramInt1 - paramInt2 + 1, paramArrayOfByte3, paramInt2, -k);
        paramArrayOfByte1[(paramInt1 - paramInt2 + 1)] = (byte)(k + i & 0xFF);
        mula_small(paramArrayOfByte2, paramArrayOfByte2, paramInt1 - paramInt2 + 1, paramArrayOfByte3, paramInt2, -i);
        i = paramArrayOfByte2[paramInt1] & 0xFF;
        paramArrayOfByte2[paramInt1] = 0;
      }
      paramArrayOfByte2[(paramInt2 - 1)] = (byte)i;
    }

    private static final int numsize(byte[] paramArrayOfByte, int paramInt)
    {
      if ((paramInt-- == 0) || (paramArrayOfByte[paramInt] != 0));
      return paramInt + 1;
    }

    private static final byte[] egcd32(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, byte[] paramArrayOfByte4)
    {
      int j = 32;
      for (int l = 0; l < 32; ++l)
      {
        int tmp17_16 = 0;
        paramArrayOfByte2[l] = tmp17_16;
        paramArrayOfByte1[l] = tmp17_16;
      }
      paramArrayOfByte1[0] = 1;
      int i = numsize(paramArrayOfByte3, 32);
      if (i == 0)
        return paramArrayOfByte2;
      byte[] arrayOfByte = new byte[32];
      while (true)
      {
        int k = j - i + 1;
        divmod(arrayOfByte, paramArrayOfByte4, j, paramArrayOfByte3, i);
        j = numsize(paramArrayOfByte4, j);
        if (j == 0)
          return paramArrayOfByte1;
        mula32(paramArrayOfByte2, paramArrayOfByte1, arrayOfByte, k, -1);
        k = i - j + 1;
        divmod(arrayOfByte, paramArrayOfByte3, i, paramArrayOfByte4, j);
        i = numsize(paramArrayOfByte3, i);
        if (i == 0)
          return paramArrayOfByte2;
        mula32(paramArrayOfByte1, paramArrayOfByte2, arrayOfByte, k, -1);
      }
    }

    private static final void unpack(Nxt.Curve25519.long10 paramlong10, byte[] paramArrayOfByte)
    {
      paramlong10._0 = (paramArrayOfByte[0] & 0xFF | (paramArrayOfByte[1] & 0xFF) << 8 | (paramArrayOfByte[2] & 0xFF) << 16 | (paramArrayOfByte[3] & 0xFF & 0x3) << 24);
      paramlong10._1 = ((paramArrayOfByte[3] & 0xFF & 0xFFFFFFFC) >> 2 | (paramArrayOfByte[4] & 0xFF) << 6 | (paramArrayOfByte[5] & 0xFF) << 14 | (paramArrayOfByte[6] & 0xFF & 0x7) << 22);
      paramlong10._2 = ((paramArrayOfByte[6] & 0xFF & 0xFFFFFFF8) >> 3 | (paramArrayOfByte[7] & 0xFF) << 5 | (paramArrayOfByte[8] & 0xFF) << 13 | (paramArrayOfByte[9] & 0xFF & 0x1F) << 21);
      paramlong10._3 = ((paramArrayOfByte[9] & 0xFF & 0xFFFFFFE0) >> 5 | (paramArrayOfByte[10] & 0xFF) << 3 | (paramArrayOfByte[11] & 0xFF) << 11 | (paramArrayOfByte[12] & 0xFF & 0x3F) << 19);
      paramlong10._4 = ((paramArrayOfByte[12] & 0xFF & 0xFFFFFFC0) >> 6 | (paramArrayOfByte[13] & 0xFF) << 2 | (paramArrayOfByte[14] & 0xFF) << 10 | (paramArrayOfByte[15] & 0xFF) << 18);
      paramlong10._5 = (paramArrayOfByte[16] & 0xFF | (paramArrayOfByte[17] & 0xFF) << 8 | (paramArrayOfByte[18] & 0xFF) << 16 | (paramArrayOfByte[19] & 0xFF & 0x1) << 24);
      paramlong10._6 = ((paramArrayOfByte[19] & 0xFF & 0xFFFFFFFE) >> 1 | (paramArrayOfByte[20] & 0xFF) << 7 | (paramArrayOfByte[21] & 0xFF) << 15 | (paramArrayOfByte[22] & 0xFF & 0x7) << 23);
      paramlong10._7 = ((paramArrayOfByte[22] & 0xFF & 0xFFFFFFF8) >> 3 | (paramArrayOfByte[23] & 0xFF) << 5 | (paramArrayOfByte[24] & 0xFF) << 13 | (paramArrayOfByte[25] & 0xFF & 0xF) << 21);
      paramlong10._8 = ((paramArrayOfByte[25] & 0xFF & 0xFFFFFFF0) >> 4 | (paramArrayOfByte[26] & 0xFF) << 4 | (paramArrayOfByte[27] & 0xFF) << 12 | (paramArrayOfByte[28] & 0xFF & 0x3F) << 20);
      paramlong10._9 = ((paramArrayOfByte[28] & 0xFF & 0xFFFFFFC0) >> 6 | (paramArrayOfByte[29] & 0xFF) << 2 | (paramArrayOfByte[30] & 0xFF) << 10 | (paramArrayOfByte[31] & 0xFF) << 18);
    }

    private static final boolean is_overflow(Nxt.Curve25519.long10 paramlong10)
    {
      return ((paramlong10._0 > 67108844L) && ((paramlong10._1 & paramlong10._3 & paramlong10._5 & paramlong10._7 & paramlong10._9) == 33554431L) && ((paramlong10._2 & paramlong10._4 & paramlong10._6 & paramlong10._8) == 67108863L)) || (paramlong10._9 > 33554431L);
    }

    private static final void pack(Nxt.Curve25519.long10 paramlong10, byte[] paramArrayOfByte)
    {
      int i = 0;
      int j = 0;
      i = ((is_overflow(paramlong10)) ? 1 : 0) - ((paramlong10._9 < 0L) ? 1 : 0);
      j = i * -33554432;
      i *= 19;
      long l = i + paramlong10._0 + (paramlong10._1 << 26);
      paramArrayOfByte[0] = (byte)(int)l;
      paramArrayOfByte[1] = (byte)(int)(l >> 8);
      paramArrayOfByte[2] = (byte)(int)(l >> 16);
      paramArrayOfByte[3] = (byte)(int)(l >> 24);
      l = (l >> 32) + (paramlong10._2 << 19);
      paramArrayOfByte[4] = (byte)(int)l;
      paramArrayOfByte[5] = (byte)(int)(l >> 8);
      paramArrayOfByte[6] = (byte)(int)(l >> 16);
      paramArrayOfByte[7] = (byte)(int)(l >> 24);
      l = (l >> 32) + (paramlong10._3 << 13);
      paramArrayOfByte[8] = (byte)(int)l;
      paramArrayOfByte[9] = (byte)(int)(l >> 8);
      paramArrayOfByte[10] = (byte)(int)(l >> 16);
      paramArrayOfByte[11] = (byte)(int)(l >> 24);
      l = (l >> 32) + (paramlong10._4 << 6);
      paramArrayOfByte[12] = (byte)(int)l;
      paramArrayOfByte[13] = (byte)(int)(l >> 8);
      paramArrayOfByte[14] = (byte)(int)(l >> 16);
      paramArrayOfByte[15] = (byte)(int)(l >> 24);
      l = (l >> 32) + paramlong10._5 + (paramlong10._6 << 25);
      paramArrayOfByte[16] = (byte)(int)l;
      paramArrayOfByte[17] = (byte)(int)(l >> 8);
      paramArrayOfByte[18] = (byte)(int)(l >> 16);
      paramArrayOfByte[19] = (byte)(int)(l >> 24);
      l = (l >> 32) + (paramlong10._7 << 19);
      paramArrayOfByte[20] = (byte)(int)l;
      paramArrayOfByte[21] = (byte)(int)(l >> 8);
      paramArrayOfByte[22] = (byte)(int)(l >> 16);
      paramArrayOfByte[23] = (byte)(int)(l >> 24);
      l = (l >> 32) + (paramlong10._8 << 12);
      paramArrayOfByte[24] = (byte)(int)l;
      paramArrayOfByte[25] = (byte)(int)(l >> 8);
      paramArrayOfByte[26] = (byte)(int)(l >> 16);
      paramArrayOfByte[27] = (byte)(int)(l >> 24);
      l = (l >> 32) + (paramlong10._9 + j << 6);
      paramArrayOfByte[28] = (byte)(int)l;
      paramArrayOfByte[29] = (byte)(int)(l >> 8);
      paramArrayOfByte[30] = (byte)(int)(l >> 16);
      paramArrayOfByte[31] = (byte)(int)(l >> 24);
    }

    private static final void cpy(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102)
    {
      paramlong101._0 = paramlong102._0;
      paramlong101._1 = paramlong102._1;
      paramlong101._2 = paramlong102._2;
      paramlong101._3 = paramlong102._3;
      paramlong101._4 = paramlong102._4;
      paramlong101._5 = paramlong102._5;
      paramlong101._6 = paramlong102._6;
      paramlong101._7 = paramlong102._7;
      paramlong101._8 = paramlong102._8;
      paramlong101._9 = paramlong102._9;
    }

    private static final void set(Nxt.Curve25519.long10 paramlong10, int paramInt)
    {
      paramlong10._0 = paramInt;
      paramlong10._1 = 0L;
      paramlong10._2 = 0L;
      paramlong10._3 = 0L;
      paramlong10._4 = 0L;
      paramlong10._5 = 0L;
      paramlong10._6 = 0L;
      paramlong10._7 = 0L;
      paramlong10._8 = 0L;
      paramlong10._9 = 0L;
    }

    private static final void add(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102, Nxt.Curve25519.long10 paramlong103)
    {
      paramlong101._0 = (paramlong102._0 + paramlong103._0);
      paramlong101._1 = (paramlong102._1 + paramlong103._1);
      paramlong101._2 = (paramlong102._2 + paramlong103._2);
      paramlong101._3 = (paramlong102._3 + paramlong103._3);
      paramlong101._4 = (paramlong102._4 + paramlong103._4);
      paramlong101._5 = (paramlong102._5 + paramlong103._5);
      paramlong101._6 = (paramlong102._6 + paramlong103._6);
      paramlong101._7 = (paramlong102._7 + paramlong103._7);
      paramlong101._8 = (paramlong102._8 + paramlong103._8);
      paramlong101._9 = (paramlong102._9 + paramlong103._9);
    }

    private static final void sub(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102, Nxt.Curve25519.long10 paramlong103)
    {
      paramlong101._0 = (paramlong102._0 - paramlong103._0);
      paramlong101._1 = (paramlong102._1 - paramlong103._1);
      paramlong101._2 = (paramlong102._2 - paramlong103._2);
      paramlong101._3 = (paramlong102._3 - paramlong103._3);
      paramlong101._4 = (paramlong102._4 - paramlong103._4);
      paramlong101._5 = (paramlong102._5 - paramlong103._5);
      paramlong101._6 = (paramlong102._6 - paramlong103._6);
      paramlong101._7 = (paramlong102._7 - paramlong103._7);
      paramlong101._8 = (paramlong102._8 - paramlong103._8);
      paramlong101._9 = (paramlong102._9 - paramlong103._9);
    }

    private static final Nxt.Curve25519.long10 mul_small(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102, long paramLong)
    {
      long l = paramlong102._8 * paramLong;
      paramlong101._8 = (l & 0x3FFFFFF);
      l = (l >> 26) + paramlong102._9 * paramLong;
      paramlong101._9 = (l & 0x1FFFFFF);
      l = 19L * (l >> 25) + paramlong102._0 * paramLong;
      paramlong101._0 = (l & 0x3FFFFFF);
      l = (l >> 26) + paramlong102._1 * paramLong;
      paramlong101._1 = (l & 0x1FFFFFF);
      l = (l >> 25) + paramlong102._2 * paramLong;
      paramlong101._2 = (l & 0x3FFFFFF);
      l = (l >> 26) + paramlong102._3 * paramLong;
      paramlong101._3 = (l & 0x1FFFFFF);
      l = (l >> 25) + paramlong102._4 * paramLong;
      paramlong101._4 = (l & 0x3FFFFFF);
      l = (l >> 26) + paramlong102._5 * paramLong;
      paramlong101._5 = (l & 0x1FFFFFF);
      l = (l >> 25) + paramlong102._6 * paramLong;
      paramlong101._6 = (l & 0x3FFFFFF);
      l = (l >> 26) + paramlong102._7 * paramLong;
      paramlong101._7 = (l & 0x1FFFFFF);
      l = (l >> 25) + paramlong101._8;
      paramlong101._8 = (l & 0x3FFFFFF);
      paramlong101._9 += (l >> 26);
      return paramlong101;
    }

    private static final Nxt.Curve25519.long10 mul(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102, Nxt.Curve25519.long10 paramlong103)
    {
      long l1 = paramlong102._0;
      long l2 = paramlong102._1;
      long l3 = paramlong102._2;
      long l4 = paramlong102._3;
      long l5 = paramlong102._4;
      long l6 = paramlong102._5;
      long l7 = paramlong102._6;
      long l8 = paramlong102._7;
      long l9 = paramlong102._8;
      long l10 = paramlong102._9;
      long l11 = paramlong103._0;
      long l12 = paramlong103._1;
      long l13 = paramlong103._2;
      long l14 = paramlong103._3;
      long l15 = paramlong103._4;
      long l16 = paramlong103._5;
      long l17 = paramlong103._6;
      long l18 = paramlong103._7;
      long l19 = paramlong103._8;
      long l20 = paramlong103._9;
      long l21 = l1 * l19 + l3 * l17 + l5 * l15 + l7 * l13 + l9 * l11 + 2L * (l2 * l18 + l4 * l16 + l6 * l14 + l8 * l12) + 38L * (l10 * l20);
      paramlong101._8 = (l21 & 0x3FFFFFF);
      l21 = (l21 >> 26) + l1 * l20 + l2 * l19 + l3 * l18 + l4 * l17 + l5 * l16 + l6 * l15 + l7 * l14 + l8 * l13 + l9 * l12 + l10 * l11;
      paramlong101._9 = (l21 & 0x1FFFFFF);
      l21 = l1 * l11 + 19L * ((l21 >> 25) + l3 * l19 + l5 * l17 + l7 * l15 + l9 * l13) + 38L * (l2 * l20 + l4 * l18 + l6 * l16 + l8 * l14 + l10 * l12);
      paramlong101._0 = (l21 & 0x3FFFFFF);
      l21 = (l21 >> 26) + l1 * l12 + l2 * l11 + 19L * (l3 * l20 + l4 * l19 + l5 * l18 + l6 * l17 + l7 * l16 + l8 * l15 + l9 * l14 + l10 * l13);
      paramlong101._1 = (l21 & 0x1FFFFFF);
      l21 = (l21 >> 25) + l1 * l13 + l3 * l11 + 19L * (l5 * l19 + l7 * l17 + l9 * l15) + 2L * (l2 * l12) + 38L * (l4 * l20 + l6 * l18 + l8 * l16 + l10 * l14);
      paramlong101._2 = (l21 & 0x3FFFFFF);
      l21 = (l21 >> 26) + l1 * l14 + l2 * l13 + l3 * l12 + l4 * l11 + 19L * (l5 * l20 + l6 * l19 + l7 * l18 + l8 * l17 + l9 * l16 + l10 * l15);
      paramlong101._3 = (l21 & 0x1FFFFFF);
      l21 = (l21 >> 25) + l1 * l15 + l3 * l13 + l5 * l11 + 19L * (l7 * l19 + l9 * l17) + 2L * (l2 * l14 + l4 * l12) + 38L * (l6 * l20 + l8 * l18 + l10 * l16);
      paramlong101._4 = (l21 & 0x3FFFFFF);
      l21 = (l21 >> 26) + l1 * l16 + l2 * l15 + l3 * l14 + l4 * l13 + l5 * l12 + l6 * l11 + 19L * (l7 * l20 + l8 * l19 + l9 * l18 + l10 * l17);
      paramlong101._5 = (l21 & 0x1FFFFFF);
      l21 = (l21 >> 25) + l1 * l17 + l3 * l15 + l5 * l13 + l7 * l11 + 19L * (l9 * l19) + 2L * (l2 * l16 + l4 * l14 + l6 * l12) + 38L * (l8 * l20 + l10 * l18);
      paramlong101._6 = (l21 & 0x3FFFFFF);
      l21 = (l21 >> 26) + l1 * l18 + l2 * l17 + l3 * l16 + l4 * l15 + l5 * l14 + l6 * l13 + l7 * l12 + l8 * l11 + 19L * (l9 * l20 + l10 * l19);
      paramlong101._7 = (l21 & 0x1FFFFFF);
      l21 = (l21 >> 25) + paramlong101._8;
      paramlong101._8 = (l21 & 0x3FFFFFF);
      paramlong101._9 += (l21 >> 26);
      return paramlong101;
    }

    private static final Nxt.Curve25519.long10 sqr(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102)
    {
      long l1 = paramlong102._0;
      long l2 = paramlong102._1;
      long l3 = paramlong102._2;
      long l4 = paramlong102._3;
      long l5 = paramlong102._4;
      long l6 = paramlong102._5;
      long l7 = paramlong102._6;
      long l8 = paramlong102._7;
      long l9 = paramlong102._8;
      long l10 = paramlong102._9;
      long l11 = l5 * l5 + 2L * (l1 * l9 + l3 * l7) + 38L * (l10 * l10) + 4L * (l2 * l8 + l4 * l6);
      paramlong101._8 = (l11 & 0x3FFFFFF);
      l11 = (l11 >> 26) + 2L * (l1 * l10 + l2 * l9 + l3 * l8 + l4 * l7 + l5 * l6);
      paramlong101._9 = (l11 & 0x1FFFFFF);
      l11 = 19L * (l11 >> 25) + l1 * l1 + 38L * (l3 * l9 + l5 * l7 + l6 * l6) + 76L * (l2 * l10 + l4 * l8);
      paramlong101._0 = (l11 & 0x3FFFFFF);
      l11 = (l11 >> 26) + 2L * (l1 * l2) + 38L * (l3 * l10 + l4 * l9 + l5 * l8 + l6 * l7);
      paramlong101._1 = (l11 & 0x1FFFFFF);
      l11 = (l11 >> 25) + 19L * (l7 * l7) + 2L * (l1 * l3 + l2 * l2) + 38L * (l5 * l9) + 76L * (l4 * l10 + l6 * l8);
      paramlong101._2 = (l11 & 0x3FFFFFF);
      l11 = (l11 >> 26) + 2L * (l1 * l4 + l2 * l3) + 38L * (l5 * l10 + l6 * l9 + l7 * l8);
      paramlong101._3 = (l11 & 0x1FFFFFF);
      l11 = (l11 >> 25) + l3 * l3 + 2L * (l1 * l5) + 38L * (l7 * l9 + l8 * l8) + 4L * (l2 * l4) + 76L * (l6 * l10);
      paramlong101._4 = (l11 & 0x3FFFFFF);
      l11 = (l11 >> 26) + 2L * (l1 * l6 + l2 * l5 + l3 * l4) + 38L * (l7 * l10 + l8 * l9);
      paramlong101._5 = (l11 & 0x1FFFFFF);
      l11 = (l11 >> 25) + 19L * (l9 * l9) + 2L * (l1 * l7 + l3 * l5 + l4 * l4) + 4L * (l2 * l6) + 76L * (l8 * l10);
      paramlong101._6 = (l11 & 0x3FFFFFF);
      l11 = (l11 >> 26) + 2L * (l1 * l8 + l2 * l7 + l3 * l6 + l4 * l5) + 38L * (l9 * l10);
      paramlong101._7 = (l11 & 0x1FFFFFF);
      l11 = (l11 >> 25) + paramlong101._8;
      paramlong101._8 = (l11 & 0x3FFFFFF);
      paramlong101._9 += (l11 >> 26);
      return paramlong101;
    }

    private static final void recip(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102, int paramInt)
    {
      Nxt.Curve25519.long10 locallong101 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10 locallong102 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10 locallong103 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10 locallong104 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10 locallong105 = new Nxt.Curve25519.long10();
      sqr(locallong102, paramlong102);
      sqr(locallong103, locallong102);
      sqr(locallong101, locallong103);
      mul(locallong103, locallong101, paramlong102);
      mul(locallong101, locallong103, locallong102);
      sqr(locallong102, locallong101);
      mul(locallong104, locallong102, locallong103);
      sqr(locallong102, locallong104);
      sqr(locallong103, locallong102);
      sqr(locallong102, locallong103);
      sqr(locallong103, locallong102);
      sqr(locallong102, locallong103);
      mul(locallong103, locallong102, locallong104);
      sqr(locallong102, locallong103);
      sqr(locallong104, locallong102);
      for (int i = 1; i < 5; ++i)
      {
        sqr(locallong102, locallong104);
        sqr(locallong104, locallong102);
      }
      mul(locallong102, locallong104, locallong103);
      sqr(locallong104, locallong102);
      sqr(locallong105, locallong104);
      for (i = 1; i < 10; ++i)
      {
        sqr(locallong104, locallong105);
        sqr(locallong105, locallong104);
      }
      mul(locallong104, locallong105, locallong102);
      for (i = 0; i < 5; ++i)
      {
        sqr(locallong102, locallong104);
        sqr(locallong104, locallong102);
      }
      mul(locallong102, locallong104, locallong103);
      sqr(locallong103, locallong102);
      sqr(locallong104, locallong103);
      for (i = 1; i < 25; ++i)
      {
        sqr(locallong103, locallong104);
        sqr(locallong104, locallong103);
      }
      mul(locallong103, locallong104, locallong102);
      sqr(locallong104, locallong103);
      sqr(locallong105, locallong104);
      for (i = 1; i < 50; ++i)
      {
        sqr(locallong104, locallong105);
        sqr(locallong105, locallong104);
      }
      mul(locallong104, locallong105, locallong103);
      for (i = 0; i < 25; ++i)
      {
        sqr(locallong105, locallong104);
        sqr(locallong104, locallong105);
      }
      mul(locallong103, locallong104, locallong102);
      sqr(locallong102, locallong103);
      sqr(locallong103, locallong102);
      if (paramInt != 0)
      {
        mul(paramlong101, paramlong102, locallong103);
      }
      else
      {
        sqr(locallong102, locallong103);
        sqr(locallong103, locallong102);
        sqr(locallong102, locallong103);
        mul(paramlong101, locallong102, locallong101);
      }
    }

    private static final int is_negative(Nxt.Curve25519.long10 paramlong10)
    {
      return (int)((((is_overflow(paramlong10)) || (paramlong10._9 < 0L)) ? 1 : 0) ^ paramlong10._0 & 1L);
    }

    private static final void sqrt(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102)
    {
      Nxt.Curve25519.long10 locallong101 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10 locallong102 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10 locallong103 = new Nxt.Curve25519.long10();
      add(locallong102, paramlong102, paramlong102);
      recip(locallong101, locallong102, 1);
      sqr(paramlong101, locallong101);
      mul(locallong103, locallong102, paramlong101);
      locallong103._0 -= 1L;
      mul(locallong102, locallong101, locallong103);
      mul(paramlong101, paramlong102, locallong102);
    }

    private static final void mont_prep(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102, Nxt.Curve25519.long10 paramlong103, Nxt.Curve25519.long10 paramlong104)
    {
      add(paramlong101, paramlong103, paramlong104);
      sub(paramlong102, paramlong103, paramlong104);
    }

    private static final void mont_add(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102, Nxt.Curve25519.long10 paramlong103, Nxt.Curve25519.long10 paramlong104, Nxt.Curve25519.long10 paramlong105, Nxt.Curve25519.long10 paramlong106, Nxt.Curve25519.long10 paramlong107)
    {
      mul(paramlong105, paramlong102, paramlong103);
      mul(paramlong106, paramlong101, paramlong104);
      add(paramlong101, paramlong105, paramlong106);
      sub(paramlong102, paramlong105, paramlong106);
      sqr(paramlong105, paramlong101);
      sqr(paramlong101, paramlong102);
      mul(paramlong106, paramlong101, paramlong107);
    }

    private static final void mont_dbl(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102, Nxt.Curve25519.long10 paramlong103, Nxt.Curve25519.long10 paramlong104, Nxt.Curve25519.long10 paramlong105, Nxt.Curve25519.long10 paramlong106)
    {
      sqr(paramlong101, paramlong103);
      sqr(paramlong102, paramlong104);
      mul(paramlong105, paramlong101, paramlong102);
      sub(paramlong102, paramlong101, paramlong102);
      mul_small(paramlong106, paramlong102, 121665L);
      add(paramlong101, paramlong101, paramlong106);
      mul(paramlong106, paramlong101, paramlong102);
    }

    private static final void x_to_y2(Nxt.Curve25519.long10 paramlong101, Nxt.Curve25519.long10 paramlong102, Nxt.Curve25519.long10 paramlong103)
    {
      sqr(paramlong101, paramlong103);
      mul_small(paramlong102, paramlong103, 486662L);
      add(paramlong101, paramlong101, paramlong102);
      paramlong101._0 += 1L;
      mul(paramlong102, paramlong101, paramlong103);
    }

    private static final void core(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, byte[] paramArrayOfByte4)
    {
      Nxt.Curve25519.long10 locallong101 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10 locallong102 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10 locallong103 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10 locallong104 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10 locallong105 = new Nxt.Curve25519.long10();
      Nxt.Curve25519.long10[] arrayOflong101 = { new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10() };
      Nxt.Curve25519.long10[] arrayOflong102 = { new Nxt.Curve25519.long10(), new Nxt.Curve25519.long10() };
      if (paramArrayOfByte4 != null)
        unpack(locallong101, paramArrayOfByte4);
      else
        set(locallong101, 9);
      set(arrayOflong101[0], 1);
      set(arrayOflong102[0], 0);
      cpy(arrayOflong101[1], locallong101);
      set(arrayOflong102[1], 1);
      int i = 32;
      while (i-- != 0)
      {
        if (i == 0)
          i = 0;
        int j = 8;
        while (j-- != 0)
        {
          int k = (paramArrayOfByte3[i] & 0xFF) >> j & 0x1;
          int l = (paramArrayOfByte3[i] & 0xFF ^ 0xFFFFFFFF) >> j & 0x1;
          localObject = arrayOflong101[l];
          Nxt.Curve25519.long10 locallong106 = arrayOflong102[l];
          Nxt.Curve25519.long10 locallong107 = arrayOflong101[k];
          Nxt.Curve25519.long10 locallong108 = arrayOflong102[k];
          mont_prep(locallong102, locallong103, (Nxt.Curve25519.long10)localObject, locallong106);
          mont_prep(locallong104, locallong105, locallong107, locallong108);
          mont_add(locallong102, locallong103, locallong104, locallong105, (Nxt.Curve25519.long10)localObject, locallong106, locallong101);
          mont_dbl(locallong102, locallong103, locallong104, locallong105, locallong107, locallong108);
        }
      }
      recip(locallong102, arrayOflong102[0], 0);
      mul(locallong101, arrayOflong101[0], locallong102);
      pack(locallong101, paramArrayOfByte1);
      if (paramArrayOfByte2 == null)
        return;
      x_to_y2(locallong103, locallong102, locallong101);
      recip(locallong104, arrayOflong102[1], 0);
      mul(locallong103, arrayOflong101[1], locallong104);
      add(locallong103, locallong103, locallong101);
      locallong103._0 += 486671L;
      locallong101._0 -= 9L;
      sqr(locallong104, locallong101);
      mul(locallong101, locallong103, locallong104);
      sub(locallong101, locallong101, locallong102);
      locallong101._0 -= 39420360L;
      mul(locallong102, locallong101, BASE_R2Y);
      if (is_negative(locallong102) != 0)
        cpy32(paramArrayOfByte2, paramArrayOfByte3);
      else
        mula_small(paramArrayOfByte2, ORDER_TIMES_8, 0, paramArrayOfByte3, 32, -1);
      byte[] arrayOfByte1 = new byte[32];
      byte[] arrayOfByte2 = new byte[64];
      Object localObject = new byte[64];
      cpy32(arrayOfByte1, ORDER);
      cpy32(paramArrayOfByte2, egcd32(arrayOfByte2, localObject, paramArrayOfByte2, arrayOfByte1));
      if ((paramArrayOfByte2[31] & 0x80) == 0)
        return;
      mula_small(paramArrayOfByte2, paramArrayOfByte2, 0, ORDER, 32, 1);
    }

    private static final class long10
    {
      public long _0;
      public long _1;
      public long _2;
      public long _3;
      public long _4;
      public long _5;
      public long _6;
      public long _7;
      public long _8;
      public long _9;

      public long10()
      {
      }

      public long10(long paramLong1, long paramLong2, long paramLong3, long paramLong4, long paramLong5, long paramLong6, long paramLong7, long paramLong8, long paramLong9, long paramLong10)
      {
        this._0 = paramLong1;
        this._1 = paramLong2;
        this._2 = paramLong3;
        this._3 = paramLong4;
        this._4 = paramLong5;
        this._5 = paramLong6;
        this._6 = paramLong7;
        this._7 = paramLong8;
        this._8 = paramLong9;
        this._9 = paramLong10;
      }
    }
  }

  static class Peer
    implements Comparable<Peer>
  {
    static final int STATE_NONCONNECTED = 0;
    static final int STATE_CONNECTED = 1;
    static final int STATE_DISCONNECTED = 2;
    int index;
    String scheme;
    int port;
    String announcedAddress;
    String hallmark;
    long accountId;
    int weight;
    int date;
    long adjustedWeight;
    String application;
    String version;
    long blacklistingTime;
    int state;
    long downloadedVolume;
    long uploadedVolume;

    Peer(String paramString)
    {
      this.announcedAddress = paramString;
    }

    static Peer addPeer(String paramString1, String paramString2)
    {
      try
      {
        new URL("http://" + paramString1);
      }
      catch (Exception localException1)
      {
        return null;
      }
      try
      {
        new URL("http://" + paramString2);
      }
      catch (Exception localException2)
      {
        paramString2 = "";
      }
      if ((paramString1.equals("localhost")) || (paramString1.equals("127.0.0.1")) || (paramString1.equals("0:0:0:0:0:0:0:1")))
        return null;
      synchronized (Nxt.peers)
      {
        if ((Nxt.myAddress != null) && (Nxt.myAddress.length() > 0) && (Nxt.myAddress.equals(paramString2)))
          return null;
        Peer localPeer = (Peer)Nxt.peers.get((paramString2.length() > 0) ? paramString2 : paramString1);
        if (localPeer == null)
        {
          localPeer = new Peer(paramString2);
          localPeer.index = (++Nxt.peerCounter);
          Nxt.peers.put((paramString2.length() > 0) ? paramString2 : paramString1, localPeer);
        }
        return localPeer;
      }
    }

    boolean analyzeHallmark(String paramString1, String paramString2)
    {
      if (paramString2 == null)
        return true;
      try
      {
        byte[] arrayOfByte1 = Nxt.convert(paramString2);
        ByteBuffer localByteBuffer = ByteBuffer.wrap(arrayOfByte1);
        localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        byte[] arrayOfByte2 = new byte[32];
        localByteBuffer.get(arrayOfByte2);
        int i = localByteBuffer.getShort();
        byte[] arrayOfByte3 = new byte[i];
        localByteBuffer.get(arrayOfByte3);
        String str = new String(arrayOfByte3, "UTF-8");
        if ((str.length() > 100) || (!str.equals(paramString1)))
          return false;
        int j = localByteBuffer.getInt();
        if ((j <= 0) || (j > 1000000000))
          return false;
        int k = localByteBuffer.getInt();
        localByteBuffer.get();
        byte[] arrayOfByte4 = new byte[64];
        localByteBuffer.get(arrayOfByte4);
        byte[] arrayOfByte5 = new byte[arrayOfByte1.length - 64];
        System.arraycopy(arrayOfByte1, 0, arrayOfByte5, 0, arrayOfByte5.length);
        if (Nxt.Crypto.verify(arrayOfByte4, arrayOfByte5, arrayOfByte2))
        {
          this.hallmark = paramString2;
          long l1 = Nxt.Account.getId(arrayOfByte2);
          Nxt.Account localAccount = (Nxt.Account)Nxt.accounts.get(Long.valueOf(l1));
          if (localAccount == null)
            return false;
          LinkedList localLinkedList = new LinkedList();
          int l = 0;
          synchronized (Nxt.peers)
          {
            this.accountId = l1;
            this.weight = j;
            this.date = k;
            Iterator localIterator1 = Nxt.peers.values().iterator();
            while (localIterator1.hasNext())
            {
              Peer localPeer1 = (Peer)localIterator1.next();
              if (localPeer1.accountId != l1)
                continue;
              localLinkedList.add(localPeer1);
              if (localPeer1.date <= l)
                continue;
              l = localPeer1.date;
            }
            long l2 = 0L;
            Iterator localIterator2 = localLinkedList.iterator();
            Peer localPeer2;
            while (localIterator2.hasNext())
            {
              localPeer2 = (Peer)localIterator2.next();
              if (localPeer2.date == l)
              {
                l2 += localPeer2.weight;
              }
              else
              {
                localPeer2.adjustedWeight = 0L;
                localPeer2.updateWeight();
              }
            }
            localIterator2 = localLinkedList.iterator();
            while (localIterator2.hasNext())
            {
              localPeer2 = (Peer)localIterator2.next();
              localPeer2.adjustedWeight = (1000000000L * localPeer2.weight / l2);
              localPeer2.updateWeight();
            }
          }
          return true;
        }
      }
      catch (Exception localException)
      {
      }
      return false;
    }

    void blacklist()
    {
      this.blacklistingTime = System.currentTimeMillis();
      JSONObject localJSONObject1 = new JSONObject();
      localJSONObject1.put("response", "processNewData");
      JSONArray localJSONArray1 = new JSONArray();
      JSONObject localJSONObject2 = new JSONObject();
      localJSONObject2.put("index", Integer.valueOf(this.index));
      localJSONArray1.add(localJSONObject2);
      localJSONObject1.put("removedKnownPeers", localJSONArray1);
      JSONArray localJSONArray2 = new JSONArray();
      JSONObject localJSONObject3 = new JSONObject();
      localJSONObject3.put("index", Integer.valueOf(this.index));
      localJSONObject3.put("announcedAddress", (this.announcedAddress.length() > 30) ? this.announcedAddress.substring(0, 30) + "..." : this.announcedAddress);
      Iterator localIterator = Nxt.wellKnownPeers.iterator();
      Object localObject;
      while (localIterator.hasNext())
      {
        localObject = (String)localIterator.next();
        if (!this.announcedAddress.equals(localObject))
          continue;
        localJSONObject3.put("wellKnown", Boolean.valueOf(true));
        break;
      }
      localJSONArray2.add(localJSONObject3);
      localJSONObject1.put("addedBlacklistedPeers", localJSONArray2);
      localIterator = Nxt.users.values().iterator();
      while (localIterator.hasNext())
      {
        localObject = (Nxt.User)localIterator.next();
        ((Nxt.User)localObject).send(localJSONObject1);
      }
    }

    public int compareTo(Peer paramPeer)
    {
      long l1 = getWeight();
      long l2 = paramPeer.getWeight();
      if (l1 > l2)
        return -1;
      if (l1 < l2)
        return 1;
      return this.index - paramPeer.index;
    }

    void connect()
    {
      JSONObject localJSONObject1 = new JSONObject();
      localJSONObject1.put("requestType", "getInfo");
      if ((Nxt.myAddress != null) && (Nxt.myAddress.length() > 0))
        localJSONObject1.put("announcedAddress", Nxt.myAddress);
      if ((Nxt.myHallmark != null) && (Nxt.myHallmark.length() > 0))
        localJSONObject1.put("hallmark", Nxt.myHallmark);
      localJSONObject1.put("application", "NRS");
      localJSONObject1.put("version", this.version);
      JSONObject localJSONObject2 = send(localJSONObject1);
      if (localJSONObject2 == null)
        return;
      this.application = ((String)localJSONObject2.get("application"));
      this.version = ((String)localJSONObject2.get("version"));
      if (analyzeHallmark(this.announcedAddress, (String)localJSONObject2.get("hallmark")))
        setState(1);
      else
        blacklist();
    }

    void deactivate()
    {
      if (this.state == 1)
        disconnect();
      setState(0);
      JSONObject localJSONObject1 = new JSONObject();
      localJSONObject1.put("response", "processNewData");
      JSONArray localJSONArray = new JSONArray();
      JSONObject localJSONObject2 = new JSONObject();
      localJSONObject2.put("index", Integer.valueOf(this.index));
      localJSONArray.add(localJSONObject2);
      localJSONObject1.put("removedActivePeers", localJSONArray);
      Object localObject1;
      if (this.announcedAddress.length() > 0)
      {
        localObject1 = new JSONArray();
        localObject2 = new JSONObject();
        ((JSONObject)localObject2).put("index", Integer.valueOf(this.index));
        ((JSONObject)localObject2).put("announcedAddress", (this.announcedAddress.length() > 30) ? this.announcedAddress.substring(0, 30) + "..." : this.announcedAddress);
        Iterator localIterator = Nxt.wellKnownPeers.iterator();
        while (localIterator.hasNext())
        {
          String str = (String)localIterator.next();
          if (!this.announcedAddress.equals(str))
            continue;
          ((JSONObject)localObject2).put("wellKnown", Boolean.valueOf(true));
          break;
        }
        ((JSONArray)localObject1).add(localObject2);
        localJSONObject1.put("addedKnownPeers", localObject1);
      }
      Object localObject2 = Nxt.users.values().iterator();
      while (((Iterator)localObject2).hasNext())
      {
        localObject1 = (Nxt.User)((Iterator)localObject2).next();
        ((Nxt.User)localObject1).send(localJSONObject1);
      }
    }

    void disconnect()
    {
      setState(2);
    }

    static Peer getAnyPeer(int paramInt, boolean paramBoolean)
    {
      synchronized (Nxt.peers)
      {
        Collection localCollection = ((HashMap)Nxt.peers.clone()).values();
        Iterator localIterator = localCollection.iterator();
        Object localObject1;
        while (localIterator.hasNext())
        {
          localObject1 = (Peer)localIterator.next();
          if ((((Peer)localObject1).blacklistingTime <= 0L) && (((Peer)localObject1).state == paramInt) && (((Peer)localObject1).announcedAddress.length() != 0) && (((!paramBoolean) || (((Peer)localObject1).getWeight() >= Nxt.pullThreshold))))
            continue;
          localIterator.remove();
        }
        if (localCollection.size() > 0)
        {
          localObject1 = (Peer[])localCollection.toArray(new Peer[0]);
          long l1 = 0L;
          for (int i = 0; i < localObject1.length; ++i)
          {
            long l3 = localObject1[i].getWeight();
            if (l3 == 0L)
              l3 = 1L;
            l1 += l3;
          }
          long l2 = ThreadLocalRandom.current().nextLong(l1);
          for (int j = 0; j < localObject1.length; ++j)
          {
            Object localObject2 = localObject1[j];
            long l4 = localObject2.getWeight();
            if (l4 == 0L)
              l4 = 1L;
            if (l2 -= l4 < 0L)
              return localObject2;
          }
        }
        return null;
      }
    }

    static int getNumberOfConnectedPublicPeers()
    {
      int i = 0;
      synchronized (Nxt.peers)
      {
        Iterator localIterator = Nxt.peers.values().iterator();
        while (localIterator.hasNext())
        {
          Peer localPeer = (Peer)localIterator.next();
          if ((localPeer.state != 1) || (localPeer.announcedAddress.length() <= 0))
            continue;
          ++i;
        }
      }
      return i;
    }

    int getWeight()
    {
      if (this.accountId == 0L)
        return 0;
      Nxt.Account localAccount = (Nxt.Account)Nxt.accounts.get(Long.valueOf(this.accountId));
      if (localAccount == null)
        return 0;
      return (int)(this.adjustedWeight * (localAccount.balance / 100L) / 1000000000L);
    }

    void removeBlacklistedStatus()
    {
      setState(0);
      this.blacklistingTime = 0L;
      JSONObject localJSONObject1 = new JSONObject();
      localJSONObject1.put("response", "processNewData");
      JSONArray localJSONArray1 = new JSONArray();
      JSONObject localJSONObject2 = new JSONObject();
      localJSONObject2.put("index", Integer.valueOf(this.index));
      localJSONArray1.add(localJSONObject2);
      localJSONObject1.put("removedBlacklistedPeers", localJSONArray1);
      JSONArray localJSONArray2 = new JSONArray();
      JSONObject localJSONObject3 = new JSONObject();
      localJSONObject3.put("index", Integer.valueOf(this.index));
      localJSONObject3.put("announcedAddress", (this.announcedAddress.length() > 30) ? this.announcedAddress.substring(0, 30) + "..." : this.announcedAddress);
      Iterator localIterator = Nxt.wellKnownPeers.iterator();
      Object localObject;
      while (localIterator.hasNext())
      {
        localObject = (String)localIterator.next();
        if (!this.announcedAddress.equals(localObject))
          continue;
        localJSONObject3.put("wellKnown", Boolean.valueOf(true));
        break;
      }
      localJSONArray2.add(localJSONObject3);
      localJSONObject1.put("addedKnownPeers", localJSONArray2);
      localIterator = Nxt.users.values().iterator();
      while (localIterator.hasNext())
      {
        localObject = (Nxt.User)localIterator.next();
        ((Nxt.User)localObject).send(localJSONObject1);
      }
    }

    void removePeer()
    {
      Object localObject2 = Nxt.peers.entrySet().iterator();
      while (((Iterator)localObject2).hasNext())
      {
        localObject1 = (Map.Entry)((Iterator)localObject2).next();
        if (((Map.Entry)localObject1).getValue() != this)
          continue;
        Nxt.peers.remove(((Map.Entry)localObject1).getKey());
        break;
      }
      Object localObject1 = new JSONObject();
      ((JSONObject)localObject1).put("response", "processNewData");
      localObject2 = new JSONArray();
      JSONObject localJSONObject = new JSONObject();
      localJSONObject.put("index", Integer.valueOf(this.index));
      ((JSONArray)localObject2).add(localJSONObject);
      ((JSONObject)localObject1).put("removedKnownPeers", localObject2);
      Iterator localIterator = Nxt.users.values().iterator();
      while (localIterator.hasNext())
      {
        Nxt.User localUser = (Nxt.User)localIterator.next();
        localUser.send((JSONObject)localObject1);
      }
    }

    static void sendToAllPeers(JSONObject paramJSONObject)
    {
      Peer[] arrayOfPeer1;
      synchronized (Nxt.peers)
      {
        arrayOfPeer1 = (Peer[])Nxt.peers.values().toArray(new Peer[0]);
      }
      Arrays.sort(arrayOfPeer1);
      for (??? : arrayOfPeer1)
      {
        if (???.getWeight() < Nxt.pushThreshold)
          return;
        if ((???.blacklistingTime != 0L) || (???.state != 1) || (???.announcedAddress.length() <= 0))
          continue;
        ???.send(paramJSONObject);
      }
    }

    JSONObject send(JSONObject paramJSONObject)
    {
      String str1 = "";
      HttpURLConnection localHttpURLConnection = null;
      JSONObject localJSONObject;
      try
      {
        if (Nxt.logPeerCommunication)
          str1 = "\"" + this.announcedAddress + "\": " + paramJSONObject.toString();
        paramJSONObject.put("protocol", Integer.valueOf(1));
        URL localURL = new URL("http://" + this.announcedAddress + ((new URL("http://" + this.announcedAddress).getPort() < 0) ? ":7874" : "") + "/nxt");
        localHttpURLConnection = (HttpURLConnection)localURL.openConnection();
        localHttpURLConnection.setRequestMethod("POST");
        localHttpURLConnection.setDoOutput(true);
        localHttpURLConnection.setConnectTimeout(Nxt.connectTimeout);
        localHttpURLConnection.setReadTimeout(Nxt.readTimeout);
        byte[] arrayOfByte1 = paramJSONObject.toString().getBytes("UTF-8");
        OutputStream localOutputStream = localHttpURLConnection.getOutputStream();
        localOutputStream.write(arrayOfByte1);
        localOutputStream.close();
        updateUploadedVolume(arrayOfByte1.length);
        if (localHttpURLConnection.getResponseCode() == 200)
        {
          InputStream localInputStream = localHttpURLConnection.getInputStream();
          ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
          byte[] arrayOfByte2 = new byte[65536];
          int i;
          while ((i = localInputStream.read(arrayOfByte2)) > 0)
            localByteArrayOutputStream.write(arrayOfByte2, 0, i);
          localInputStream.close();
          String str2 = localByteArrayOutputStream.toString("UTF-8");
          if (Nxt.logPeerCommunication)
            str1 = str1 + " >>> " + str2;
          updateDownloadedVolume(str2.getBytes("UTF-8").length);
          localJSONObject = (JSONObject)JSONValue.parse(str2);
        }
        else
        {
          disconnect();
          if (Nxt.logPeerCommunication)
            str1 = str1 + " >>> Peer responded with HTTP " + localHttpURLConnection.getResponseCode() + " code!";
          localJSONObject = null;
        }
      }
      catch (Exception localException)
      {
        if (this.state == 0)
          blacklist();
        else
          disconnect();
        if (Nxt.logPeerCommunication)
          str1 = str1 + " >>> " + localException.toString();
        localJSONObject = null;
      }
      if (localHttpURLConnection != null)
        localHttpURLConnection.disconnect();
      if (Nxt.logPeerCommunication)
        Nxt.logMessage(str1 + "\n");
      return localJSONObject;
    }

    void setState(int paramInt)
    {
      JSONObject localJSONObject1;
      JSONArray localJSONArray;
      JSONObject localJSONObject2;
      Iterator localIterator;
      Object localObject;
      if ((this.state == 0) && (paramInt != 0))
      {
        localJSONObject1 = new JSONObject();
        localJSONObject1.put("response", "processNewData");
        if (this.announcedAddress.length() > 0)
        {
          localJSONArray = new JSONArray();
          localJSONObject2 = new JSONObject();
          localJSONObject2.put("index", Integer.valueOf(this.index));
          localJSONArray.add(localJSONObject2);
          localJSONObject1.put("removedKnownPeers", localJSONArray);
        }
        localJSONArray = new JSONArray();
        localJSONObject2 = new JSONObject();
        localJSONObject2.put("index", Integer.valueOf(this.index));
        if (paramInt == 2)
          localJSONObject2.put("disconnected", Boolean.valueOf(true));
        localIterator = Nxt.peers.entrySet().iterator();
        while (localIterator.hasNext())
        {
          localObject = (Map.Entry)localIterator.next();
          if (((Map.Entry)localObject).getValue() != this)
            continue;
          localJSONObject2.put("address", (((String)((Map.Entry)localObject).getKey()).length() > 30) ? ((String)((Map.Entry)localObject).getKey()).substring(0, 30) + "..." : (String)((Map.Entry)localObject).getKey());
          break;
        }
        localJSONObject2.put("announcedAddress", (this.announcedAddress.length() > 30) ? this.announcedAddress.substring(0, 30) + "..." : this.announcedAddress);
        localJSONObject2.put("weight", Integer.valueOf(getWeight()));
        localJSONObject2.put("downloaded", Long.valueOf(this.downloadedVolume));
        localJSONObject2.put("uploaded", Long.valueOf(this.uploadedVolume));
        localJSONObject2.put("software", ((this.application == null) ? "?" : this.application) + " (" + ((this.version == null) ? "?" : this.version) + ")");
        localIterator = Nxt.wellKnownPeers.iterator();
        while (localIterator.hasNext())
        {
          localObject = (String)localIterator.next();
          if (!this.announcedAddress.equals(localObject))
            continue;
          localJSONObject2.put("wellKnown", Boolean.valueOf(true));
          break;
        }
        localJSONArray.add(localJSONObject2);
        localJSONObject1.put("addedActivePeers", localJSONArray);
        localIterator = Nxt.users.values().iterator();
        while (localIterator.hasNext())
        {
          localObject = (Nxt.User)localIterator.next();
          ((Nxt.User)localObject).send(localJSONObject1);
        }
      }
      else if ((this.state != 0) && (paramInt != 0))
      {
        localJSONObject1 = new JSONObject();
        localJSONObject1.put("response", "processNewData");
        localJSONArray = new JSONArray();
        localJSONObject2 = new JSONObject();
        localJSONObject2.put("index", Integer.valueOf(this.index));
        localJSONObject2.put((paramInt == 1) ? "connected" : "disconnected", Boolean.valueOf(true));
        localJSONArray.add(localJSONObject2);
        localJSONObject1.put("changedActivePeers", localJSONArray);
        localIterator = Nxt.users.values().iterator();
        while (localIterator.hasNext())
        {
          localObject = (Nxt.User)localIterator.next();
          ((Nxt.User)localObject).send(localJSONObject1);
        }
      }
      this.state = paramInt;
    }

    void updateDownloadedVolume(int paramInt)
    {
      this.downloadedVolume += paramInt;
      JSONObject localJSONObject1 = new JSONObject();
      localJSONObject1.put("response", "processNewData");
      JSONArray localJSONArray = new JSONArray();
      JSONObject localJSONObject2 = new JSONObject();
      localJSONObject2.put("index", Integer.valueOf(this.index));
      localJSONObject2.put("downloaded", Long.valueOf(this.downloadedVolume));
      localJSONArray.add(localJSONObject2);
      localJSONObject1.put("changedActivePeers", localJSONArray);
      Iterator localIterator = Nxt.users.values().iterator();
      while (localIterator.hasNext())
      {
        Nxt.User localUser = (Nxt.User)localIterator.next();
        localUser.send(localJSONObject1);
      }
    }

    void updateUploadedVolume(int paramInt)
    {
      this.uploadedVolume += paramInt;
      JSONObject localJSONObject1 = new JSONObject();
      localJSONObject1.put("response", "processNewData");
      JSONArray localJSONArray = new JSONArray();
      JSONObject localJSONObject2 = new JSONObject();
      localJSONObject2.put("index", Integer.valueOf(this.index));
      localJSONObject2.put("uploaded", Long.valueOf(this.uploadedVolume));
      localJSONArray.add(localJSONObject2);
      localJSONObject1.put("changedActivePeers", localJSONArray);
      Iterator localIterator = Nxt.users.values().iterator();
      while (localIterator.hasNext())
      {
        Nxt.User localUser = (Nxt.User)localIterator.next();
        localUser.send(localJSONObject1);
      }
    }

    void updateWeight()
    {
      JSONObject localJSONObject1 = new JSONObject();
      localJSONObject1.put("response", "processNewData");
      JSONArray localJSONArray = new JSONArray();
      JSONObject localJSONObject2 = new JSONObject();
      localJSONObject2.put("index", Integer.valueOf(this.index));
      localJSONObject2.put("weight", Integer.valueOf(getWeight()));
      localJSONArray.add(localJSONObject2);
      localJSONObject1.put("changedActivePeers", localJSONArray);
      Iterator localIterator = Nxt.users.values().iterator();
      while (localIterator.hasNext())
      {
        Nxt.User localUser = (Nxt.User)localIterator.next();
        localUser.send(localJSONObject1);
      }
    }
  }

  static class Transaction
    implements Comparable<Transaction>, Serializable
  {
    static final long serialVersionUID = 0L;
    static final byte TYPE_PAYMENT = 0;
    static final byte TYPE_MESSAGING = 1;
    static final byte TYPE_COLORED_COINS = 2;
    static final byte SUBTYPE_PAYMENT_ORDINARY_PAYMENT = 0;
    static final byte SUBTYPE_MESSAGING_ARBITRARY_MESSAGE = 0;
    static final byte SUBTYPE_MESSAGING_ALIAS_ASSIGNMENT = 1;
    static final byte SUBTYPE_COLORED_COINS_ASSET_ISSUANCE = 0;
    static final byte SUBTYPE_COLORED_COINS_ASSET_TRANSFER = 1;
    static final byte SUBTYPE_COLORED_COINS_ASK_ORDER_PLACEMENT = 2;
    static final byte SUBTYPE_COLORED_COINS_BID_ORDER_PLACEMENT = 3;
    static final byte SUBTYPE_COLORED_COINS_ASK_ORDER_CANCELLATION = 4;
    static final byte SUBTYPE_COLORED_COINS_BID_ORDER_CANCELLATION = 5;
    static final int ASSET_ISSUANCE_FEE = 1000;
    byte type;
    byte subtype;
    int timestamp;
    short deadline;
    byte[] senderPublicKey;
    long recipient;
    int amount;
    int fee;
    long referencedTransaction;
    byte[] signature;
    Nxt.Transaction.Attachment attachment;
    int index;
    long block;
    int height;

    Transaction(byte paramByte1, byte paramByte2, int paramInt1, short paramShort, byte[] paramArrayOfByte1, long paramLong1, int paramInt2, int paramInt3, long paramLong2, byte[] paramArrayOfByte2)
    {
      this.type = paramByte1;
      this.subtype = paramByte2;
      this.timestamp = paramInt1;
      this.deadline = paramShort;
      this.senderPublicKey = paramArrayOfByte1;
      this.recipient = paramLong1;
      this.amount = paramInt2;
      this.fee = paramInt3;
      this.referencedTransaction = paramLong2;
      this.signature = paramArrayOfByte2;
      this.height = 2147483647;
    }

    public int compareTo(Transaction paramTransaction)
    {
      if (this.height < paramTransaction.height)
        return -1;
      if (this.height > paramTransaction.height)
        return 1;
      if (this.fee * 1048576L / getBytes().length > paramTransaction.fee * 1048576L / paramTransaction.getBytes().length)
        return -1;
      if (this.fee * 1048576L / getBytes().length < paramTransaction.fee * 1048576L / paramTransaction.getBytes().length)
        return 1;
      if (this.timestamp < paramTransaction.timestamp)
        return -1;
      if (this.timestamp > paramTransaction.timestamp)
        return 1;
      if (this.index < paramTransaction.index)
        return -1;
      if (this.index > paramTransaction.index)
        return 1;
      return 0;
    }

    byte[] getBytes()
    {
      ByteBuffer localByteBuffer = ByteBuffer.allocate(128 + ((this.attachment == null) ? 0 : this.attachment.getBytes().length));
      localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
      localByteBuffer.put(this.type);
      localByteBuffer.put(this.subtype);
      localByteBuffer.putInt(this.timestamp);
      localByteBuffer.putShort(this.deadline);
      localByteBuffer.put(this.senderPublicKey);
      localByteBuffer.putLong(this.recipient);
      localByteBuffer.putInt(this.amount);
      localByteBuffer.putInt(this.fee);
      localByteBuffer.putLong(this.referencedTransaction);
      localByteBuffer.put(this.signature);
      if (this.attachment != null)
        localByteBuffer.put(this.attachment.getBytes());
      return localByteBuffer.array();
    }

    long getId()
      throws Exception
    {
      byte[] arrayOfByte = MessageDigest.getInstance("SHA-256").digest(getBytes());
      BigInteger localBigInteger = new BigInteger(1, new byte[] { arrayOfByte[7], arrayOfByte[6], arrayOfByte[5], arrayOfByte[4], arrayOfByte[3], arrayOfByte[2], arrayOfByte[1], arrayOfByte[0] });
      return localBigInteger.longValue();
    }

    JSONObject getJSONObject()
    {
      JSONObject localJSONObject = new JSONObject();
      localJSONObject.put("type", Byte.valueOf(this.type));
      localJSONObject.put("subtype", Byte.valueOf(this.subtype));
      localJSONObject.put("timestamp", Integer.valueOf(this.timestamp));
      localJSONObject.put("deadline", Short.valueOf(this.deadline));
      localJSONObject.put("senderPublicKey", Nxt.convert(this.senderPublicKey));
      localJSONObject.put("recipient", Nxt.convert(this.recipient));
      localJSONObject.put("amount", Integer.valueOf(this.amount));
      localJSONObject.put("fee", Integer.valueOf(this.fee));
      localJSONObject.put("referencedTransaction", Nxt.convert(this.referencedTransaction));
      localJSONObject.put("signature", Nxt.convert(this.signature));
      if (this.attachment != null)
        localJSONObject.put("attachment", this.attachment.getJSONObject());
      return localJSONObject;
    }

    static Transaction getTransaction(ByteBuffer paramByteBuffer)
    {
      byte b1 = paramByteBuffer.get();
      byte b2 = paramByteBuffer.get();
      int i = paramByteBuffer.getInt();
      short s = paramByteBuffer.getShort();
      byte[] arrayOfByte1 = new byte[32];
      paramByteBuffer.get(arrayOfByte1);
      long l1 = paramByteBuffer.getLong();
      int j = paramByteBuffer.getInt();
      int k = paramByteBuffer.getInt();
      long l2 = paramByteBuffer.getLong();
      byte[] arrayOfByte2 = new byte[64];
      paramByteBuffer.get(arrayOfByte2);
      Transaction localTransaction = new Transaction(b1, b2, i, s, arrayOfByte1, l1, j, k, l2, arrayOfByte2);
      int l;
      byte[] arrayOfByte3;
      int i1;
      byte[] arrayOfByte4;
      switch (b1)
      {
      case 1:
        switch (b2)
        {
        case 1:
          l = paramByteBuffer.get();
          arrayOfByte3 = new byte[l];
          paramByteBuffer.get(arrayOfByte3);
          i1 = paramByteBuffer.getShort();
          arrayOfByte4 = new byte[i1];
          paramByteBuffer.get(arrayOfByte4);
          try
          {
            localTransaction.attachment = new Nxt.Transaction.MessagingAliasAssignmentAttachment(new String(arrayOfByte3, "UTF-8"), new String(arrayOfByte4, "UTF-8"));
          }
          catch (Exception localException1)
          {
          }
        }
        break;
      case 2:
        long l3;
        long l4;
        switch (b2)
        {
        case 0:
          l = paramByteBuffer.get();
          arrayOfByte3 = new byte[l];
          paramByteBuffer.get(arrayOfByte3);
          i1 = paramByteBuffer.getShort();
          arrayOfByte4 = new byte[i1];
          paramByteBuffer.get(arrayOfByte4);
          int i2 = paramByteBuffer.getInt();
          try
          {
            localTransaction.attachment = new Nxt.Transaction.ColoredCoinsAssetIssuanceAttachment(new String(arrayOfByte3, "UTF-8"), new String(arrayOfByte4, "UTF-8"), i2);
          }
          catch (Exception localException2)
          {
          }
          break;
        case 1:
          l3 = paramByteBuffer.getLong();
          i1 = paramByteBuffer.getInt();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsAssetTransferAttachment(l3, i1);
          break;
        case 2:
          l3 = paramByteBuffer.getLong();
          i1 = paramByteBuffer.getInt();
          l4 = paramByteBuffer.getLong();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment(l3, i1, l4);
          break;
        case 3:
          l3 = paramByteBuffer.getLong();
          i1 = paramByteBuffer.getInt();
          l4 = paramByteBuffer.getLong();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment(l3, i1, l4);
          break;
        case 4:
          l3 = paramByteBuffer.getLong();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsAskOrderCancellationAttachment(l3);
          break;
        case 5:
          l3 = paramByteBuffer.getLong();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsBidOrderCancellationAttachment(l3);
        }
      }
      return localTransaction;
    }

    static Transaction getTransaction(JSONObject paramJSONObject)
    {
      byte b1 = ((Long)paramJSONObject.get("type")).byteValue();
      byte b2 = ((Long)paramJSONObject.get("subtype")).byteValue();
      int i = ((Long)paramJSONObject.get("timestamp")).intValue();
      short s = ((Long)paramJSONObject.get("deadline")).shortValue();
      byte[] arrayOfByte1 = Nxt.convert((String)paramJSONObject.get("senderPublicKey"));
      long l1 = new BigInteger((String)paramJSONObject.get("recipient")).longValue();
      int j = ((Long)paramJSONObject.get("amount")).intValue();
      int k = ((Long)paramJSONObject.get("fee")).intValue();
      long l2 = new BigInteger((String)paramJSONObject.get("referencedTransaction")).longValue();
      byte[] arrayOfByte2 = Nxt.convert((String)paramJSONObject.get("signature"));
      Transaction localTransaction = new Transaction(b1, b2, i, s, arrayOfByte1, l1, j, k, l2, arrayOfByte2);
      JSONObject localJSONObject = (JSONObject)paramJSONObject.get("attachment");
      String str1;
      String str2;
      switch (b1)
      {
      case 1:
        switch (b2)
        {
        case 1:
          str1 = (String)localJSONObject.get("alias");
          str2 = (String)localJSONObject.get("uri");
          localTransaction.attachment = new Nxt.Transaction.MessagingAliasAssignmentAttachment(str1.trim(), str2.trim());
        }
        break;
      case 2:
        int l;
        long l3;
        long l4;
        switch (b2)
        {
        case 0:
          str1 = (String)localJSONObject.get("name");
          str2 = (String)localJSONObject.get("description");
          l = ((Long)localJSONObject.get("quantity")).intValue();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsAssetIssuanceAttachment(str1.trim(), str2.trim(), l);
          break;
        case 1:
          l3 = new BigInteger((String)localJSONObject.get("asset")).longValue();
          l = ((Long)localJSONObject.get("quantity")).intValue();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsAssetTransferAttachment(l3, l);
          break;
        case 2:
          l3 = new BigInteger((String)localJSONObject.get("asset")).longValue();
          l = ((Long)localJSONObject.get("quantity")).intValue();
          l4 = ((Long)localJSONObject.get("price")).longValue();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment(l3, l, l4);
          break;
        case 3:
          l3 = new BigInteger((String)localJSONObject.get("asset")).longValue();
          l = ((Long)localJSONObject.get("quantity")).intValue();
          l4 = ((Long)localJSONObject.get("price")).longValue();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment(l3, l, l4);
          break;
        case 4:
          l3 = new BigInteger((String)localJSONObject.get("order")).longValue();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsAskOrderCancellationAttachment(l3);
          break;
        case 5:
          l3 = new BigInteger((String)localJSONObject.get("order")).longValue();
          localTransaction.attachment = new Nxt.Transaction.ColoredCoinsBidOrderCancellationAttachment(l3);
        }
      }
      return localTransaction;
    }

    static void loadTransactions(String paramString)
      throws Exception
    {
      FileInputStream localFileInputStream = new FileInputStream(paramString);
      ObjectInputStream localObjectInputStream = new ObjectInputStream(localFileInputStream);
      Nxt.transactionCounter = localObjectInputStream.readInt();
      Nxt.transactions = (HashMap)localObjectInputStream.readObject();
      localObjectInputStream.close();
      localFileInputStream.close();
    }

    static void processTransactions(JSONObject paramJSONObject, String paramString)
    {
      JSONArray localJSONArray1 = (JSONArray)paramJSONObject.get(paramString);
      JSONArray localJSONArray2 = new JSONArray();
      int i = 0;
      while (i < localJSONArray1.size())
      {
        JSONObject localJSONObject2 = (JSONObject)localJSONArray1.get(i);
        Transaction localTransaction = getTransaction(localJSONObject2);
        try
        {
          int j = Nxt.getEpochTime(System.currentTimeMillis());
          if ((localTransaction.timestamp <= j + 15) && (localTransaction.deadline >= 1) && (localTransaction.timestamp + localTransaction.deadline * 60 >= j) && (localTransaction.fee > 0))
            if (localTransaction.validateAttachment())
              synchronized (Nxt.transactions)
              {
                long l1 = localTransaction.getId();
                if ((Nxt.transactions.get(Long.valueOf(l1)) == null) && (Nxt.unconfirmedTransactions.get(Long.valueOf(l1)) == null) && (Nxt.doubleSpendingTransactions.get(Long.valueOf(l1)) == null) && (localTransaction.verify()))
                {
                  long l2 = Nxt.Account.getId(localTransaction.senderPublicKey);
                  Nxt.Account localAccount = (Nxt.Account)Nxt.accounts.get(Long.valueOf(l2));
                  int k;
                  if (localAccount == null)
                  {
                    k = 1;
                  }
                  else
                  {
                    int l = localTransaction.amount + localTransaction.fee;
                    synchronized (localAccount)
                    {
                      if (localAccount.unconfirmedBalance < l * 100L)
                      {
                        k = 1;
                      }
                      else
                      {
                        k = 0;
                        localAccount.setUnconfirmedBalance(localAccount.unconfirmedBalance - l * 100L);
                        if (localTransaction.type == 2)
                          if (localTransaction.subtype == 1)
                          {
                            localObject1 = (Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localTransaction.attachment;
                            if ((localAccount.unconfirmedAssetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localObject1).asset)) == null) || (((Integer)localAccount.unconfirmedAssetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localObject1).asset))).intValue() < ((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localObject1).quantity))
                            {
                              k = 1;
                              localAccount.setUnconfirmedBalance(localAccount.unconfirmedBalance + l * 100L);
                            }
                            else
                            {
                              localAccount.unconfirmedAssetBalances.put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localObject1).asset), Integer.valueOf(((Integer)localAccount.unconfirmedAssetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localObject1).asset))).intValue() - ((Nxt.Transaction.ColoredCoinsAssetTransferAttachment)localObject1).quantity));
                            }
                          }
                          else if (localTransaction.subtype == 2)
                          {
                            localObject1 = (Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localTransaction.attachment;
                            if ((localAccount.unconfirmedAssetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localObject1).asset)) == null) || (((Integer)localAccount.unconfirmedAssetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localObject1).asset))).intValue() < ((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localObject1).quantity))
                            {
                              k = 1;
                              localAccount.setUnconfirmedBalance(localAccount.unconfirmedBalance + l * 100L);
                            }
                            else
                            {
                              localAccount.unconfirmedAssetBalances.put(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localObject1).asset), Integer.valueOf(((Integer)localAccount.unconfirmedAssetBalances.get(Long.valueOf(((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localObject1).asset))).intValue() - ((Nxt.Transaction.ColoredCoinsAskOrderPlacementAttachment)localObject1).quantity));
                            }
                          }
                          else if (localTransaction.subtype == 3)
                          {
                            localObject1 = (Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)localTransaction.attachment;
                            if (localAccount.unconfirmedBalance < ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)localObject1).quantity * ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)localObject1).price)
                            {
                              k = 1;
                              localAccount.setUnconfirmedBalance(localAccount.unconfirmedBalance + l * 100L);
                            }
                            else
                            {
                              localAccount.setUnconfirmedBalance(localAccount.unconfirmedBalance - ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)localObject1).quantity * ((Nxt.Transaction.ColoredCoinsBidOrderPlacementAttachment)localObject1).price);
                            }
                          }
                      }
                    }
                  }
                  localTransaction.index = (++Nxt.transactionCounter);
                  if (k != 0)
                  {
                    Nxt.doubleSpendingTransactions.put(Long.valueOf(localTransaction.getId()), localTransaction);
                  }
                  else
                  {
                    Nxt.unconfirmedTransactions.put(Long.valueOf(localTransaction.getId()), localTransaction);
                    if (paramString.equals("transactions"))
                      localJSONArray2.add(localJSONObject2);
                  }
                  JSONObject localJSONObject3 = new JSONObject();
                  localJSONObject3.put("response", "processNewData");
                  ??? = new JSONArray();
                  Object localObject1 = new JSONObject();
                  ((JSONObject)localObject1).put("index", Integer.valueOf(localTransaction.index));
                  ((JSONObject)localObject1).put("timestamp", Integer.valueOf(localTransaction.timestamp));
                  ((JSONObject)localObject1).put("deadline", Short.valueOf(localTransaction.deadline));
                  ((JSONObject)localObject1).put("recipient", Nxt.convert(localTransaction.recipient));
                  ((JSONObject)localObject1).put("amount", Integer.valueOf(localTransaction.amount));
                  ((JSONObject)localObject1).put("fee", Integer.valueOf(localTransaction.fee));
                  ((JSONObject)localObject1).put("sender", Nxt.convert(l2));
                  ((JSONObject)localObject1).put("id", Nxt.convert(localTransaction.getId()));
                  ((JSONArray)???).add(localObject1);
                  if (k != 0)
                    localJSONObject3.put("addedDoubleSpendingTransactions", ???);
                  else
                    localJSONObject3.put("addedUnconfirmedTransactions", ???);
                  Iterator localIterator = Nxt.users.values().iterator();
                  while (localIterator.hasNext())
                  {
                    Nxt.User localUser = (Nxt.User)localIterator.next();
                    localUser.send(localJSONObject3);
                  }
                }
              }
        }
        catch (Exception localException)
        {
          Nxt.logMessage("15: " + localException.toString());
          ++i;
        }
      }
      if (localJSONArray2.size() <= 0)
        return;
      JSONObject localJSONObject1 = new JSONObject();
      localJSONObject1.put("requestType", "processTransactions");
      localJSONObject1.put("transactions", localJSONArray2);
      Nxt.Peer.sendToAllPeers(localJSONObject1);
    }

    static void saveTransactions(String paramString)
      throws Exception
    {
      synchronized (Nxt.transactions)
      {
        FileOutputStream localFileOutputStream = new FileOutputStream(paramString);
        ObjectOutputStream localObjectOutputStream = new ObjectOutputStream(localFileOutputStream);
        localObjectOutputStream.writeInt(Nxt.transactionCounter);
        localObjectOutputStream.writeObject(Nxt.transactions);
        localObjectOutputStream.close();
        localFileOutputStream.close();
      }
    }

    void sign(String paramString)
    {
      this.signature = Nxt.Crypto.sign(getBytes(), paramString);
      try
      {
        while (!verify())
        {
          this.timestamp += 1;
          this.signature = new byte[64];
          this.signature = Nxt.Crypto.sign(getBytes(), paramString);
        }
      }
      catch (Exception localException)
      {
        Nxt.logMessage("16: " + localException.toString());
      }
    }

    boolean validateAttachment()
    {
      switch (this.type)
      {
      case 0:
        switch (this.subtype)
        {
        case 0:
          return (this.amount > 0) && (this.amount <= 1000000000);
        }
        return false;
      case 1:
        if (Nxt.Block.getLastBlock().height < 22000)
          return false;
        switch (this.subtype)
        {
        case 1:
          try
          {
            Nxt.Transaction.MessagingAliasAssignmentAttachment localMessagingAliasAssignmentAttachment = (Nxt.Transaction.MessagingAliasAssignmentAttachment)this.attachment;
            if ((this.recipient != 1739068987193023818L) || (this.amount != 0) || (localMessagingAliasAssignmentAttachment.alias.length() == 0) || (localMessagingAliasAssignmentAttachment.alias.length() > 100) || (localMessagingAliasAssignmentAttachment.uri.length() > 1000))
              return false;
            String str = localMessagingAliasAssignmentAttachment.alias.toLowerCase();
            for (int i = 0; i < str.length(); ++i)
              if ("0123456789abcdefghijklmnopqrstuvwxyz".indexOf(str.charAt(i)) < 0)
                return false;
            Nxt.Alias localAlias;
            synchronized (Nxt.aliases)
            {
              localAlias = (Nxt.Alias)Nxt.aliases.get(str);
            }
            return (localAlias == null) || (localAlias.account.id == Nxt.Account.getId(this.senderPublicKey));
          }
          catch (Exception localException)
          {
            return false;
          }
        }
        return false;
      }
      return false;
    }

    boolean verify()
      throws Exception
    {
      Nxt.Account localAccount = (Nxt.Account)Nxt.accounts.get(Long.valueOf(Nxt.Account.getId(this.senderPublicKey)));
      if (localAccount == null)
        return false;
      if (localAccount.publicKey == null)
        localAccount.publicKey = this.senderPublicKey;
      else if (!Arrays.equals(this.senderPublicKey, localAccount.publicKey))
        return false;
      byte[] arrayOfByte = getBytes();
      for (int i = 64; i < 128; ++i)
        arrayOfByte[i] = 0;
      return Nxt.Crypto.verify(this.signature, arrayOfByte, this.senderPublicKey);
    }

    static abstract interface Attachment
    {
      public abstract byte[] getBytes();

      public abstract JSONObject getJSONObject();
    }

    static class ColoredCoinsAskOrderCancellationAttachment
      implements Nxt.Transaction.Attachment, Serializable
    {
      static final long serialVersionUID = 0L;
      long order;

      ColoredCoinsAskOrderCancellationAttachment(long paramLong)
      {
        this.order = paramLong;
      }

      public byte[] getBytes()
      {
        ByteBuffer localByteBuffer = ByteBuffer.allocate(8);
        localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        localByteBuffer.putLong(this.order);
        return localByteBuffer.array();
      }

      public JSONObject getJSONObject()
      {
        JSONObject localJSONObject = new JSONObject();
        localJSONObject.put("order", Nxt.convert(this.order));
        return localJSONObject;
      }
    }

    static class ColoredCoinsAskOrderPlacementAttachment
      implements Nxt.Transaction.Attachment, Serializable
    {
      static final long serialVersionUID = 0L;
      long asset;
      int quantity;
      long price;

      ColoredCoinsAskOrderPlacementAttachment(long paramLong1, int paramInt, long paramLong2)
      {
        this.asset = paramLong1;
        this.quantity = paramInt;
        this.price = paramLong2;
      }

      public byte[] getBytes()
      {
        ByteBuffer localByteBuffer = ByteBuffer.allocate(20);
        localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        localByteBuffer.putLong(this.asset);
        localByteBuffer.putInt(this.quantity);
        localByteBuffer.putLong(this.price);
        return localByteBuffer.array();
      }

      public JSONObject getJSONObject()
      {
        JSONObject localJSONObject = new JSONObject();
        localJSONObject.put("asset", Nxt.convert(this.asset));
        localJSONObject.put("quantity", Integer.valueOf(this.quantity));
        localJSONObject.put("price", Long.valueOf(this.price));
        return localJSONObject;
      }
    }

    static class ColoredCoinsAssetIssuanceAttachment
      implements Nxt.Transaction.Attachment, Serializable
    {
      static final long serialVersionUID = 0L;
      String name;
      String description;
      int quantity;

      ColoredCoinsAssetIssuanceAttachment(String paramString1, String paramString2, int paramInt)
      {
        this.name = paramString1;
        this.description = ((paramString2 == null) ? "" : paramString2);
        this.quantity = paramInt;
      }

      public byte[] getBytes()
      {
        try
        {
          byte[] arrayOfByte1 = this.name.getBytes("UTF-8");
          byte[] arrayOfByte2 = this.description.getBytes("UTF-8");
          ByteBuffer localByteBuffer = ByteBuffer.allocate(1 + arrayOfByte1.length + 2 + arrayOfByte2.length + 4);
          localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
          localByteBuffer.put((byte)arrayOfByte1.length);
          localByteBuffer.put(arrayOfByte1);
          localByteBuffer.putShort((short)arrayOfByte2.length);
          localByteBuffer.put(arrayOfByte2);
          localByteBuffer.putInt(this.quantity);
          return localByteBuffer.array();
        }
        catch (Exception localException)
        {
        }
        return null;
      }

      public JSONObject getJSONObject()
      {
        JSONObject localJSONObject = new JSONObject();
        localJSONObject.put("name", this.name);
        localJSONObject.put("description", this.description);
        localJSONObject.put("quantity", Integer.valueOf(this.quantity));
        return localJSONObject;
      }
    }

    static class ColoredCoinsAssetTransferAttachment
      implements Nxt.Transaction.Attachment, Serializable
    {
      static final long serialVersionUID = 0L;
      long asset;
      int quantity;

      ColoredCoinsAssetTransferAttachment(long paramLong, int paramInt)
      {
        this.asset = paramLong;
        this.quantity = paramInt;
      }

      public byte[] getBytes()
      {
        ByteBuffer localByteBuffer = ByteBuffer.allocate(12);
        localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        localByteBuffer.putLong(this.asset);
        localByteBuffer.putInt(this.quantity);
        return localByteBuffer.array();
      }

      public JSONObject getJSONObject()
      {
        JSONObject localJSONObject = new JSONObject();
        localJSONObject.put("asset", Nxt.convert(this.asset));
        localJSONObject.put("quantity", Integer.valueOf(this.quantity));
        return localJSONObject;
      }
    }

    static class ColoredCoinsBidOrderCancellationAttachment
      implements Nxt.Transaction.Attachment, Serializable
    {
      static final long serialVersionUID = 0L;
      long order;

      ColoredCoinsBidOrderCancellationAttachment(long paramLong)
      {
        this.order = paramLong;
      }

      public byte[] getBytes()
      {
        ByteBuffer localByteBuffer = ByteBuffer.allocate(8);
        localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        localByteBuffer.putLong(this.order);
        return localByteBuffer.array();
      }

      public JSONObject getJSONObject()
      {
        JSONObject localJSONObject = new JSONObject();
        localJSONObject.put("order", Nxt.convert(this.order));
        return localJSONObject;
      }
    }

    static class ColoredCoinsBidOrderPlacementAttachment
      implements Nxt.Transaction.Attachment, Serializable
    {
      static final long serialVersionUID = 0L;
      long asset;
      int quantity;
      long price;

      ColoredCoinsBidOrderPlacementAttachment(long paramLong1, int paramInt, long paramLong2)
      {
        this.asset = paramLong1;
        this.quantity = paramInt;
        this.price = paramLong2;
      }

      public byte[] getBytes()
      {
        ByteBuffer localByteBuffer = ByteBuffer.allocate(20);
        localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        localByteBuffer.putLong(this.asset);
        localByteBuffer.putInt(this.quantity);
        localByteBuffer.putLong(this.price);
        return localByteBuffer.array();
      }

      public JSONObject getJSONObject()
      {
        JSONObject localJSONObject = new JSONObject();
        localJSONObject.put("asset", Nxt.convert(this.asset));
        localJSONObject.put("quantity", Integer.valueOf(this.quantity));
        localJSONObject.put("price", Long.valueOf(this.price));
        return localJSONObject;
      }
    }

    static class MessagingAliasAssignmentAttachment
      implements Nxt.Transaction.Attachment, Serializable
    {
      static final long serialVersionUID = 0L;
      String alias;
      String uri;

      MessagingAliasAssignmentAttachment(String paramString1, String paramString2)
      {
        this.alias = paramString1;
        this.uri = paramString2;
      }

      public byte[] getBytes()
      {
        try
        {
          byte[] arrayOfByte1 = this.alias.getBytes("UTF-8");
          byte[] arrayOfByte2 = this.uri.getBytes("UTF-8");
          ByteBuffer localByteBuffer = ByteBuffer.allocate(1 + arrayOfByte1.length + 2 + arrayOfByte2.length);
          localByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
          localByteBuffer.put((byte)arrayOfByte1.length);
          localByteBuffer.put(arrayOfByte1);
          localByteBuffer.putShort((short)arrayOfByte2.length);
          localByteBuffer.put(arrayOfByte2);
          return localByteBuffer.array();
        }
        catch (Exception localException)
        {
        }
        return null;
      }

      public JSONObject getJSONObject()
      {
        JSONObject localJSONObject = new JSONObject();
        localJSONObject.put("alias", this.alias);
        localJSONObject.put("uri", this.uri);
        return localJSONObject;
      }
    }
  }

  static class User
  {
    ConcurrentLinkedQueue<JSONObject> pendingResponses = new ConcurrentLinkedQueue();
    AsyncContext asyncContext;
    String secretPhrase;

    void deinitializeKeyPair()
    {
      this.secretPhrase = null;
    }

    BigInteger initializeKeyPair(String paramString)
      throws Exception
    {
      this.secretPhrase = paramString;
      byte[] arrayOfByte = MessageDigest.getInstance("SHA-256").digest(Nxt.Crypto.getPublicKey(paramString));
      BigInteger localBigInteger = new BigInteger(1, new byte[] { arrayOfByte[7], arrayOfByte[6], arrayOfByte[5], arrayOfByte[4], arrayOfByte[3], arrayOfByte[2], arrayOfByte[1], arrayOfByte[0] });
      return localBigInteger;
    }

    void send(JSONObject paramJSONObject)
    {
      synchronized (this)
      {
        if (this.asyncContext == null)
        {
          this.pendingResponses.offer(paramJSONObject);
        }
        else
        {
          JSONArray localJSONArray = new JSONArray();
          Object localObject1;
          while ((localObject1 = (JSONObject)this.pendingResponses.poll()) != null)
            localJSONArray.add(localObject1);
          localJSONArray.add(paramJSONObject);
          JSONObject localJSONObject = new JSONObject();
          localJSONObject.put("responses", localJSONArray);
          try
          {
            this.asyncContext.getResponse().setContentType("text/plain; charset=UTF-8");
            ServletOutputStream localServletOutputStream = this.asyncContext.getResponse().getOutputStream();
            localServletOutputStream.write(localJSONObject.toString().getBytes("UTF-8"));
            localServletOutputStream.close();
            this.asyncContext.complete();
            this.asyncContext = null;
          }
          catch (Exception localException)
          {
            Nxt.logMessage("17: " + localException.toString());
          }
        }
      }
    }
  }

  static class UserAsyncListener
    implements AsyncListener
  {
    Nxt.User user;

    UserAsyncListener(Nxt.User paramUser)
    {
      this.user = paramUser;
    }

    public void onComplete(AsyncEvent paramAsyncEvent)
      throws IOException
    {
    }

    public void onError(AsyncEvent paramAsyncEvent)
      throws IOException
    {
      this.user.asyncContext.getResponse().setContentType("text/plain; charset=UTF-8");
      ServletOutputStream localServletOutputStream = this.user.asyncContext.getResponse().getOutputStream();
      localServletOutputStream.write(new JSONObject().toString().getBytes("UTF-8"));
      localServletOutputStream.close();
      this.user.asyncContext.complete();
      this.user.asyncContext = null;
    }

    public void onStartAsync(AsyncEvent paramAsyncEvent)
      throws IOException
    {
    }

    public void onTimeout(AsyncEvent paramAsyncEvent)
      throws IOException
    {
      this.user.asyncContext.getResponse().setContentType("text/plain; charset=UTF-8");
      ServletOutputStream localServletOutputStream = this.user.asyncContext.getResponse().getOutputStream();
      localServletOutputStream.write(new JSONObject().toString().getBytes("UTF-8"));
      localServletOutputStream.close();
      this.user.asyncContext.complete();
      this.user.asyncContext = null;
    }
  }
}

/* Location:           /tmp/nxt/webapps/root/WEB-INF/classes/
 * Qualified Name:     Nxt
 * JD-Core Version:    0.5.4
 */

