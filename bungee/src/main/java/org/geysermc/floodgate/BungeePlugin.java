package org.geysermc.floodgate;

import lombok.Getter;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.event.ServerConnectedEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.ChatMessageType;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;
import net.md_5.bungee.protocol.packet.Handshake;
import org.geysermc.floodgate.HandshakeHandler.HandshakeResult;
import org.geysermc.floodgate.HandshakeHandler.ResultType;
import org.geysermc.floodgate.command.LinkAccountCommand;
import org.geysermc.floodgate.command.UnlinkAccountCommand;
import org.geysermc.floodgate.util.BedrockData;
import org.geysermc.floodgate.util.CommandUtil;
import org.geysermc.floodgate.util.ReflectionUtil;

import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import java.util.HashSet;
import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.IntStream;
import me.vik1395.BungeeAuthAPI.RequestHandler;

import static org.geysermc.floodgate.util.BedrockData.FLOODGATE_IDENTIFIER;

public class BungeePlugin extends Plugin implements Listener {
    @Getter private static BungeePlugin instance;
    private static Field extraHandshakeData;

    @Getter private BungeeFloodgateConfig config;
    @Getter private PlayerLink playerLink;
    private BungeeDebugger debugger;
    private HandshakeHandler handshakeHandler;

    private static final int PASSWORD_LENGTH = 8;
    private static final char[] PASSWORD_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();

    private final Random random = new SecureRandom();

    private Plugin bungeeAuth;

    private HashSet<String> preLoginUsernames;

    @Override
    public void onLoad() {
        instance = this;
        if (!getDataFolder().exists()) {
            getDataFolder().mkdir();
        }
        config = FloodgateConfig.load(getLogger(), getDataFolder().toPath().resolve("config.yml"), BungeeFloodgateConfig.class);
        playerLink = PlayerLink.initialize(getLogger(), getDataFolder().toPath(), config);
        handshakeHandler = new HandshakeHandler(config.getPrivateKey(), true, config.getUsernamePrefix(), config.isReplaceSpaces());

        this.preLoginUsernames = new HashSet<String>();
    }

    @Override
    public void onEnable() {
        getProxy().getPluginManager().registerListener(this, this);
        if (config.isDebug()) {
            debugger = new BungeeDebugger();
        }

        this.bungeeAuth = getProxy().getPluginManager().getPlugin("BungeeAuth");

        CommandUtil commandUtil = new CommandUtil();
        getProxy().getPluginManager().registerCommand(this, new LinkAccountCommand(playerLink, commandUtil));
        getProxy().getPluginManager().registerCommand(this, new UnlinkAccountCommand(playerLink, commandUtil));
    }

    @Override
    public void onDisable() {
        if (config.isDebug()) {
            getLogger().warning("Please note that it is not possible to reload this plugin when debug mode is enabled. At least for now");
        }
        playerLink.stop();
    }

    @EventHandler(priority = EventPriority.LOW)
    public void onServerConnect(ServerConnectEvent e) {
        // Passes the information through to the connecting server if enabled
        if (config.isSendFloodgateData() && FloodgateAPI.isBedrockPlayer(e.getPlayer())) {
            Handshake handshake = ReflectionUtil.getCastedValue(e.getPlayer().getPendingConnection(), "handshake", Handshake.class);
            handshake.setHost(
                    handshake.getHost().split("\0")[0] + '\0' + // Ensures that only the hostname remains!
                            FLOODGATE_IDENTIFIER + '\0' + FloodgateAPI.getEncryptedData(e.getPlayer().getUniqueId())
            );
            // Bungeecord will add his data after our data
        }
    }

    public String getRandomPassword() {
        StringBuilder generatedPassword = new StringBuilder(8);
        IntStream.rangeClosed(1, PASSWORD_LENGTH)
            .map(i -> random.nextInt(PASSWORD_CHARACTERS.length - 1))
            .mapToObj(pos -> PASSWORD_CHARACTERS[pos])
            .forEach(generatedPassword::append);

        return generatedPassword.toString();
    }

    @EventHandler(priority = EventPriority.LOW)
    public void onPreLogin(PreLoginEvent event) {
        event.registerIntent(this);
        getProxy().getScheduler().runAsync(this, () -> {
            String extraData = ReflectionUtil.getCastedValue(event.getConnection(), extraHandshakeData, String.class);

            HandshakeResult result = handshakeHandler.handle(extraData);
            switch (result.getResultType()) {
                case SUCCESS:
                    break;
                case EXCEPTION:
                    event.setCancelReason(config.getMessages().getInvalidKey());
                    break;
                case INVALID_DATA_LENGTH:
                    event.setCancelReason(String.format(
                            config.getMessages().getInvalidArgumentsLength(),
                            BedrockData.EXPECTED_LENGTH, result.getBedrockData().getDataLength()
                    ));
                    break;
            }

            if (result.getResultType() != ResultType.SUCCESS) {
                // only continue when SUCCESS
                event.completeIntent(this);
                return;
            }

            FloodgatePlayer player = result.getFloodgatePlayer();
            FloodgateAPI.addEncryptedData(player.getCorrectUniqueId(), result.getHandshakeData()[2] + '\0' + result.getHandshakeData()[3]);

            event.getConnection().setOnlineMode(false);
            event.getConnection().setUniqueId(player.getCorrectUniqueId());

            if (this.bungeeAuth != null) {
                this.preLoginUsernames.add(player.getCorrectUsername());
                getLogger().info("Player " + player.getUsername() + " with Java Username " + player.getCorrectUsername() + " logged with floodgate and queue for bypass BungeeAuth");
            }

            ReflectionUtil.setValue(event.getConnection(), "name", player.getCorrectUsername());
            Object channelWrapper = ReflectionUtil.getValue(event.getConnection(), "ch");
            SocketAddress remoteAddress = ReflectionUtil.getCastedValue(channelWrapper, "remoteAddress", SocketAddress.class);
            if (!(remoteAddress instanceof InetSocketAddress)) {
                getLogger().info(
                        "Player " + player.getUsername() + " doesn't use an InetSocketAddress. " +
                        "It uses " + remoteAddress.getClass().getSimpleName() + ". Ignoring the player, I guess."
                );
            } else {
                ReflectionUtil.setValue(
                        channelWrapper, "remoteAddress",
                        new InetSocketAddress(result.getBedrockData().getIp(), ((InetSocketAddress) remoteAddress).getPort())
                );
            }
            event.completeIntent(this);
        });
    }

    @EventHandler
    public void onServerConnected(ServerConnectedEvent serverConnectedEvent) {
        ProxiedPlayer player = serverConnectedEvent.getPlayer();
        String name = player.getName();
        getProxy().getScheduler().runAsync(this, () -> {
            if (this.bungeeAuth != null && this.preLoginUsernames.contains(name)) {
                this.preLoginUsernames.remove(name);
                RequestHandler requestHandler = new RequestHandler();
                if (!requestHandler.isRegistered(name)) {
                    String password = getRandomPassword();
                    requestHandler.forceRegister(player, password);
                    player.sendMessage(ChatMessageType.CHAT, TextComponent.fromLegacyText("Auto register with password: " + password));
                }
                requestHandler.forceLogin(name);
                getLogger().info("Player " + player.getName() + " forced login with BungeeAuth");
            }
        });
    }

    @EventHandler
    public void onPlayerDisconnect(PlayerDisconnectEvent event) {
        FloodgatePlayer player = FloodgateAPI.getPlayerByConnection(event.getPlayer().getPendingConnection());
        if (player != null) {
            FloodgateAPI.players.remove(player.getCorrectUniqueId());
            FloodgateAPI.removeEncryptedData(player.getCorrectUniqueId());
            System.out.println("Removed " + player.getUsername() + " " + event.getPlayer().getUniqueId());
        }
    }

    static {
        ReflectionUtil.setPrefix("net.md_5.bungee");
        Class<?> initial_handler = ReflectionUtil.getPrefixedClass("connection.InitialHandler");
        extraHandshakeData = ReflectionUtil.getField(initial_handler, "extraDataInHandshake");
    }
}
